// Copyright © .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Win32MetaGeneration
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Reflection.Metadata;
    using System.Reflection.PortableExecutable;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Threading;
    using Microsoft.CodeAnalysis;
    using Microsoft.CodeAnalysis.CSharp;
    using Microsoft.CodeAnalysis.CSharp.Syntax;
    using Microsoft.CodeAnalysis.Editing;
    using static Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

    internal class Generator : IDisposable
    {
        /// <summary>
        /// This is the preferred capitalizations for modules and class names.
        /// If they are not in this list, the capitalization will come from the metadata assembly.
        /// </summary>
        private static readonly HashSet<string> CanonicalCapitalizations = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "AdvApi32",
            "Crypt32",
            "Gdi32",
            "NCrypt",
            "ComCtl32",
            "CryptNet",
            "DnsApi",
            "BCrypt",
            "NTDll",
            "Ole32",
            "WinHttp",
            "Kernel32",
            "WebSocket",
            "User32",
        };

        private static readonly AttributeSyntax InAttributeSyntax = Attribute(IdentifierName("In"));
        private static readonly AttributeSyntax OutAttributeSyntax = Attribute(IdentifierName("Out"));
        private static readonly AttributeSyntax FlagsAttributeSyntax = Attribute(IdentifierName("Flags"));

        private static readonly SyntaxTokenList PublicModifiers = TokenList(Token(SyntaxKind.PublicKeyword));

        private readonly FileStream metadataStream;
        private readonly PEReader peReader;
        private readonly MetadataReader mr;
        private readonly SyntaxGenerator generator;
        private readonly SignatureTypeProvider signatureTypeProvider;
        private readonly CustomAttributeTypeProvider customAttributeTypeProvider;
        private readonly Dictionary<string, List<MemberDeclarationSyntax>> modulesAndMembers = new Dictionary<string, List<MemberDeclarationSyntax>>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// The structs, enums, delegates and other supporting types for extern methods.
        /// </summary>
        private readonly Dictionary<TypeDefinitionHandle, MemberDeclarationSyntax> types = new Dictionary<TypeDefinitionHandle, MemberDeclarationSyntax>();

        /// <summary>
        /// The set of types currently being generated so we don't stack overflow for self-referencing types.
        /// </summary>
        private readonly HashSet<TypeDefinitionHandle> typesGenerating = new HashSet<TypeDefinitionHandle>();

        internal Generator(string pathToMetaLibrary, string languageName)
        {
            var project = CSharpCompilation.Create("PInvoke")
                .AddReferences(
                    MetadataReference.CreateFromFile(pathToMetaLibrary, MetadataReferenceProperties.Assembly),
                    MetadataReference.CreateFromFile(typeof(IntPtr).Assembly.Location));

            this.metadataStream = new FileStream(pathToMetaLibrary, FileMode.Open, FileAccess.Read, FileShare.Read);
            this.peReader = new PEReader(this.metadataStream);
            this.mr = this.peReader.GetMetadataReader();

            var workspace = new AdhocWorkspace();
            this.generator = SyntaxGenerator.GetGenerator(workspace, languageName);
            this.signatureTypeProvider = new SignatureTypeProvider(project, this.generator, this);
            this.customAttributeTypeProvider = new CustomAttributeTypeProvider();
        }

        internal CompilationUnitSyntax CompilationUnit
        {
            get => CompilationUnit()
                .AddMembers(this.modulesAndMembers.Select(kv =>
                    ClassDeclaration(Identifier(kv.Key))
                        .AddModifiers(Token(SyntaxKind.PublicKeyword), Token(SyntaxKind.StaticKeyword))
                        .AddMembers(kv.Value.ToArray())).ToArray())
                        .AddMembers(this.types.Values.ToArray())
                .AddUsings(
                    UsingDirective(IdentifierName(nameof(System))),
                    UsingDirective(ParseName("System.Runtime.InteropServices")))
                .NormalizeWhitespace();
        }

        public void Dispose()
        {
            this.peReader.Dispose();
            this.metadataStream.Dispose();
        }

        /// <summary>
        /// Generates a projection of Win32 APIs.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        internal void GenerateAllExternMethods(CancellationToken cancellationToken)
        {
            foreach (MethodDefinitionHandle methodHandle in this.GetApisClass().GetMethods())
            {
                cancellationToken.ThrowIfCancellationRequested();

                var methodDefinition = this.mr.GetMethodDefinition(methodHandle);
                ////if (!this.mr.StringComparer.Equals(methodDefinition.Name, "GetCurrentDirectoryW"))
                ////{
                ////    continue;
                ////}

                this.GenerateExternMethod(methodDefinition);
            }
        }

        internal void GenerateExternMethod(MethodDefinition methodDefinition)
        {
            MethodImport import = methodDefinition.GetImport();
            if (import.Name.IsNil)
            {
                // Not an exported method.
                return;
            }

            MethodSignature<TypeSyntax> signature = methodDefinition.DecodeSignature(this.signatureTypeProvider, null!);

            var methodName = this.mr.GetString(methodDefinition.Name);
            var moduleName = this.GetNormalizedModuleName(import);

            MethodDeclarationSyntax methodDeclaration = MethodDeclaration(
                List<AttributeListSyntax>().Add(AttributeList().AddAttributes(this.CreateDllImportAttribute(methodDefinition, import, moduleName))),
                modifiers: TokenList(Token(SyntaxKind.ExternKeyword), Token(SyntaxKind.StaticKeyword), Token(SyntaxKind.UnsafeKeyword)),
                signature.ReturnType,
                explicitInterfaceSpecifier: null!,
                Identifier(methodName),
                TypeParameterList(),
                this.CreateParameterList(methodDefinition, signature),
                List<TypeParameterConstraintClauseSyntax>(),
                body: null!,
                Token(SyntaxKind.SemicolonToken));

            List<MemberDeclarationSyntax> methodsList = this.GetModuleMemberList(moduleName);
            methodsList.Add(methodDeclaration);
        }

        internal void GenerateInteropType(TypeDefinitionHandle typeDefHandle)
        {
            if (!this.typesGenerating.Add(typeDefHandle))
            {
                return;
            }

            TypeDefinition typeDef = this.mr.GetTypeDefinition(typeDefHandle);
            var baseTypeRef = this.mr.GetTypeReference((TypeReferenceHandle)typeDef.BaseType);
            MemberDeclarationSyntax typeDeclaration;

            if (this.mr.StringComparer.Equals(baseTypeRef.Name, nameof(ValueType)) && this.mr.StringComparer.Equals(baseTypeRef.Namespace, nameof(System)))
            {
                typeDeclaration = this.CreateInteropStruct(typeDef);
            }
            else if (this.mr.StringComparer.Equals(baseTypeRef.Name, nameof(Enum)) && this.mr.StringComparer.Equals(baseTypeRef.Namespace, nameof(System)))
            {
                typeDeclaration = this.CreateInteropEnum(typeDef);
            }
            else if (this.mr.StringComparer.Equals(baseTypeRef.Name, nameof(MulticastDelegate)) && this.mr.StringComparer.Equals(baseTypeRef.Namespace, nameof(System)))
            {
                typeDeclaration = this.CreateInteropDelegate(typeDef);
            }
            else
            {
                return; // not yet supported.
            }

            this.types.Add(typeDefHandle, typeDeclaration);
        }

        private DelegateDeclarationSyntax CreateInteropDelegate(TypeDefinition typeDef)
        {
            // TODO: UnmanagedFunctionPointerAttribute
            string name = this.mr.GetString(typeDef.Name);

            MethodDefinition invokeMethodDef = typeDef.GetMethods().Select(this.mr.GetMethodDefinition).Single(def => this.mr.StringComparer.Equals(def.Name, "Invoke"));
            MethodSignature<TypeSyntax> signature = invokeMethodDef.DecodeSignature(this.signatureTypeProvider, null!);

            return DelegateDeclaration(signature.ReturnType, name)
                .WithParameterList(this.CreateParameterList(invokeMethodDef, signature))
                .AddModifiers(Token(SyntaxKind.PublicKeyword), Token(SyntaxKind.UnsafeKeyword));
        }

        private StructDeclarationSyntax CreateInteropStruct(TypeDefinition typeDef)
        {
            string name = this.mr.GetString(typeDef.Name);

            var members = new List<MemberDeclarationSyntax>();
            foreach (FieldDefinitionHandle fieldDefHandle in typeDef.GetFields())
            {
                // TODO: fix handling of fixed size buffers (e.g. WIN32_FIND_DATAA)
                FieldDefinition fieldDef = this.mr.GetFieldDefinition(fieldDefHandle);
                string fieldName = this.mr.GetString(fieldDef.Name);

                CustomAttribute? fixedBufferAttribute = null;
                foreach (CustomAttributeHandle attHandle in fieldDef.GetCustomAttributes())
                {
                    CustomAttribute att = this.mr.GetCustomAttribute(attHandle);
                    if (this.IsAttribute(att, "System.Runtime.CompilerServices", nameof(FixedBufferAttribute)))
                    {
                        fixedBufferAttribute = att;
                        break;
                    }
                }

                FieldDeclarationSyntax field;
                if (fixedBufferAttribute.HasValue)
                {
                    CustomAttributeValue<TypeSyntax> attributeArgs = fixedBufferAttribute.Value.DecodeValue(this.customAttributeTypeProvider);
                    TypeSyntax fieldType = (TypeSyntax)attributeArgs.FixedArguments[0].Value!;
                    ExpressionSyntax size = LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal((int)attributeArgs.FixedArguments[1].Value!));
                    field = FieldDeclaration(
                        VariableDeclaration(fieldType))
                        .AddDeclarationVariables(
                            VariableDeclarator(fieldName)
                                .WithArgumentList(BracketedArgumentList(SingletonSeparatedList(Argument(size)))))
                        .AddModifiers(Token(SyntaxKind.PublicKeyword), Token(SyntaxKind.UnsafeKeyword), Token(SyntaxKind.FixedKeyword));
                }
                else
                {
                    TypeSyntax fieldType = fieldDef.DecodeSignature(this.signatureTypeProvider, null!);
                    field = FieldDeclaration(VariableDeclaration(fieldType).AddVariables(VariableDeclarator(fieldName)))
                        .AddModifiers(Token(SyntaxKind.PublicKeyword));
                    if (fieldType is PointerTypeSyntax)
                    {
                        field = field.AddModifiers(Token(SyntaxKind.UnsafeKeyword));
                    }
                }

                members.Add(field);
            }

            // TODO: specify Pack size where necessary
            return StructDeclaration(name)
                .AddMembers(members.ToArray());
        }

        private EnumDeclarationSyntax CreateInteropEnum(TypeDefinition typeDef)
        {
            var enumValues = new List<EnumMemberDeclarationSyntax>();
            TypeSyntax? enumBaseType = null;
            foreach (FieldDefinitionHandle fieldDefHandle in typeDef.GetFields())
            {
                FieldDefinition fieldDef = this.mr.GetFieldDefinition(fieldDefHandle);
                string enumValueName = this.mr.GetString(fieldDef.Name);
                ConstantHandle valueHandle = fieldDef.GetDefaultValue();
                if (valueHandle.IsNil)
                {
                    enumBaseType = fieldDef.DecodeSignature(this.signatureTypeProvider, null!);
                    continue;
                }

                Constant value = this.mr.GetConstant(valueHandle);
                enumValues.Add(EnumMemberDeclaration(Identifier(enumValueName)).WithEqualsValue(EqualsValueClause(this.ToExpressionSyntax(value))));
            }

            if (enumBaseType is null)
            {
                throw new NotSupportedException("Unknown enum type.");
            }

            bool flagsEnum = false;
            foreach (CustomAttributeHandle attributeHandle in typeDef.GetCustomAttributes())
            {
                CustomAttribute attribute = this.mr.GetCustomAttribute(attributeHandle);
                if (this.IsAttribute(attribute, nameof(System), "FlagsAttribute"))
                {
                    flagsEnum = true;
                    break;
                }
            }

            var name = this.mr.GetString(typeDef.Name);
            EnumDeclarationSyntax result = EnumDeclaration(name)
                .AddBaseListTypes(SimpleBaseType(enumBaseType))
                .AddMembers(enumValues.ToArray())
                .WithModifiers(PublicModifiers);

            if (flagsEnum)
            {
                result = result.AddAttributeLists(
                    AttributeList().AddAttributes(FlagsAttributeSyntax));
            }

            return result;
        }

        private bool IsAttribute(CustomAttribute attribute, string ns, string name)
        {
            MemberReference memberReference = this.mr.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
            TypeReference parentRef = this.mr.GetTypeReference((TypeReferenceHandle)memberReference.Parent);
            return this.mr.StringComparer.Equals(parentRef.Name, name) && this.mr.StringComparer.Equals(parentRef.Namespace, ns);
        }

        private List<MemberDeclarationSyntax> GetModuleMemberList(string moduleName)
        {
            if (!this.modulesAndMembers.TryGetValue(moduleName, out var methodsList))
            {
                this.modulesAndMembers.Add(moduleName, methodsList = new List<MemberDeclarationSyntax>());
            }

            return methodsList;
        }

        private string GetNormalizedModuleName(MethodImport import)
        {
            ModuleReference module = this.mr.GetModuleReference(import.Module);
            string moduleName = this.mr.GetString(module.Name);
            if (CanonicalCapitalizations.TryGetValue(moduleName, out string? canonicalModuleName))
            {
                moduleName = canonicalModuleName;
            }

            return moduleName;
        }

        private AttributeSyntax CreateDllImportAttribute(MethodDefinition methodDefinition, MethodImport import, string moduleName)
        {
            var dllImportAttribute = Attribute(IdentifierName("DllImport")).AddArgumentListArguments(
                AttributeArgument(LiteralExpression(SyntaxKind.StringLiteralExpression, Literal(moduleName))),
                AttributeArgument(LiteralExpression(SyntaxKind.TrueLiteralExpression)).WithNameEquals(NameEquals(nameof(DllImportAttribute.ExactSpelling))));
            return dllImportAttribute;
        }

        private TypeDefinition GetApisClass() => this.mr.TypeDefinitions.Select(this.mr.GetTypeDefinition).Single(td => this.mr.StringComparer.Equals(td.Name, "Apis") && this.mr.StringComparer.Equals(td.Namespace, "Microsoft.Windows.Sdk"));

        private ParameterListSyntax CreateParameterList(MethodDefinition methodDefinition, MethodSignature<TypeSyntax> signature)
            => ParameterList().AddParameters(methodDefinition.GetParameters().Select(this.mr.GetParameter).Where(p => !p.Name.IsNil).Select(p => this.CreateParameter(signature, p)).ToArray());

        private ParameterSyntax CreateParameter(MethodSignature<TypeSyntax> methodSignature, Parameter parameter)
        {
            string name = this.mr.GetString(parameter.Name);
            TypeSyntax type = this.ReinterpretParameterType(methodSignature.ParameterTypes[parameter.SequenceNumber - 1], parameter);

            // Determine the custom attributes to apply.
            var attributes = AttributeList();
            if (type is PointerTypeSyntax)
            {
                if ((parameter.Attributes & ParameterAttributes.In) == ParameterAttributes.In)
                {
                    attributes = attributes.AddAttributes(InAttributeSyntax);
                }

                if ((parameter.Attributes & ParameterAttributes.Out) == ParameterAttributes.Out)
                {
                    attributes = attributes.AddAttributes(OutAttributeSyntax);
                }
            }

            var modifiers = TokenList();

            ParameterSyntax parameterSyntax = Parameter(
                attributes.Attributes.Count > 0 ? List<AttributeListSyntax>().Add(attributes) : List<AttributeListSyntax>(),
                modifiers,
                type,
                Identifier(name),
                @default: null);

            return parameterSyntax;
        }

        private TypeSyntax ReinterpretParameterType(TypeSyntax originalParameterType, Parameter parameter)
        {
            bool inAttribute = (parameter.Attributes & ParameterAttributes.In) == ParameterAttributes.In;
            UnmanagedType? unmanagedType = this.GetUnmanagedType(parameter.GetMarshallingDescriptor());
            if (unmanagedType == UnmanagedType.LPWStr && originalParameterType is PointerTypeSyntax { ElementType: PredefinedTypeSyntax { Keyword: SyntaxToken token } } && "ushort".Equals(token.Value))
            {
                return PointerType(PredefinedType(Token(SyntaxKind.CharKeyword)));
            }

            if (unmanagedType == UnmanagedType.LPArray)
            {
                MarshalAsAttribute marshalAs = this.ToMarshalAsAttribute(parameter.GetMarshallingDescriptor());
                if (marshalAs.ArraySubType == UnmanagedType.LPWStr && originalParameterType is PointerTypeSyntax { ElementType: PredefinedTypeSyntax { Keyword: SyntaxToken token2 } } && "ushort".Equals(token2.Value))
                {
                    return PointerType(PredefinedType(Token(SyntaxKind.CharKeyword)));
                }
            }

            return originalParameterType;
        }

        private UnmanagedType? GetUnmanagedType(BlobHandle blobHandle)
        {
            if (blobHandle.IsNil)
            {
                return null;
            }

            BlobReader br = this.mr.GetBlobReader(blobHandle);
            UnmanagedType unmgdType = (UnmanagedType)br.ReadByte();
            return unmgdType;
        }

        private MarshalAsAttribute ToMarshalAsAttribute(BlobHandle blobHandle)
        {
            BlobReader br = this.mr.GetBlobReader(blobHandle);
            UnmanagedType unmgdType = (UnmanagedType)br.ReadByte();
            MarshalAsAttribute ma = new MarshalAsAttribute(unmgdType);
            switch (unmgdType)
            {
                case UnmanagedType.Interface:
                case UnmanagedType.IUnknown:
                case UnmanagedType.IDispatch:
                    if (br.RemainingBytes == 0)
                    {
                        break;
                    }

                    ma.IidParameterIndex = br.ReadCompressedInteger();
                    break;

                case UnmanagedType.ByValArray:
                    if (br.RemainingBytes == 0)
                    {
                        break;
                    }

                    ma.SizeConst = br.ReadCompressedInteger();

                    if (br.RemainingBytes == 0)
                    {
                        break;
                    }

                    ma.ArraySubType = (UnmanagedType)br.ReadCompressedInteger();

                    break;

                case UnmanagedType.SafeArray:
                    if (br.RemainingBytes == 0)
                    {
                        break;
                    }

                    ma.SafeArraySubType = (VarEnum)br.ReadCompressedInteger();

                    if (br.RemainingBytes == 0)
                    {
                        break;
                    }
                    ////string udtName = br.ReadSerializedString();
                    ////ma.SafeArrayUserDefinedSubType = Helpers.LoadTypeFromAssemblyQualifiedName(udtName, module.GetRoAssembly(), ignoreCase: false, throwOnError: false);
                    break;

                case UnmanagedType.LPArray:
                    if (br.RemainingBytes == 0)
                    {
                        break;
                    }

                    ma.ArraySubType = (UnmanagedType)br.ReadCompressedInteger();

                    if (br.RemainingBytes == 0)
                    {
                        break;
                    }

                    ma.SizeParamIndex = (short)br.ReadCompressedInteger();

                    if (br.RemainingBytes == 0)
                    {
                        break;
                    }

                    ma.SizeConst = br.ReadCompressedInteger();
                    break;

                case UnmanagedType.CustomMarshaler:
                    if (br.RemainingBytes == 0)
                    {
                        break;
                    }

                    br.ReadSerializedString(); // Skip the typelib guid.

                    if (br.RemainingBytes == 0)
                    {
                        break;
                    }

                    br.ReadSerializedString(); // Skip name of native type.

                    if (br.RemainingBytes == 0)
                    {
                        break;
                    }

                    ma.MarshalType = br.ReadSerializedString();
                    ////ma.MarshalTypeRef = Helpers.LoadTypeFromAssemblyQualifiedName(ma.MarshalType, module.GetRoAssembly(), ignoreCase: false, throwOnError: false);

                    if (br.RemainingBytes == 0)
                    {
                        break;
                    }

                    ma.MarshalCookie = br.ReadSerializedString();
                    break;

                default:
                    break;
            }

            return ma;
        }

        private ExpressionSyntax ToExpressionSyntax(Constant constant)
        {
            var blobReader = this.mr.GetBlobReader(constant.Value);
            return constant.TypeCode switch
            {
                ConstantTypeCode.Boolean => blobReader.ReadBoolean() ? LiteralExpression(SyntaxKind.TrueLiteralExpression) : LiteralExpression(SyntaxKind.FalseLiteralExpression),
                ConstantTypeCode.Char => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(blobReader.ReadChar())),
                ConstantTypeCode.SByte => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(blobReader.ReadSByte())),
                ConstantTypeCode.Byte => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(blobReader.ReadByte())),
                ConstantTypeCode.Int16 => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(blobReader.ReadInt16())),
                ConstantTypeCode.UInt16 => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(blobReader.ReadUInt16())),
                ConstantTypeCode.Int32 => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(blobReader.ReadInt32())),
                ConstantTypeCode.UInt32 => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(blobReader.ReadUInt32())),
                ConstantTypeCode.Int64 => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(blobReader.ReadInt64())),
                ConstantTypeCode.UInt64 => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(blobReader.ReadUInt64())),
                ConstantTypeCode.Single => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(blobReader.ReadSingle())),
                ConstantTypeCode.Double => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(blobReader.ReadDouble())),
                ConstantTypeCode.String => blobReader.ReadSerializedString() is string value ? LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(value)) : LiteralExpression(SyntaxKind.NullLiteralExpression),
                _ => throw new NotSupportedException("ConstantTypeCode not supported: " + constant.TypeCode),
            };
        }
    }
}
