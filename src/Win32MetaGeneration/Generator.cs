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
            "BCrypt",
            "Cabinet",
            "CfgMgr32",
            "CodeGeneration",
            "CodeGeneration.Debugging",
            "CodeGenerationAttributes",
            "Crypt32",
            "DbgHelp",
            "DwmApi",
            "Fusion",
            "Gdi32",
            "Hid",
            "ImageHlp",
            "IPHlpApi",
            "Kernel32",
            "Magnification",
            "MSCorEE",
            "Msi",
            "NCrypt",
            "NetApi32",
            "NewDev",
            "NTDll",
            "Ole32",
            "Psapi",
            "SetupApi",
            "SHCore",
            "Shell32",
            "User32",
            "Userenv",
            "UxTheme",
            "Win32",
            "Win32MetaGeneration",
            "Windows.Core",
            "Windows.ShellScalingApi",
            "WinUsb",
            "WtsApi32",
        };

        private static readonly HashSet<string> CSharpKeywords = new HashSet<string>(StringComparer.Ordinal)
        {
            "event",
        };

        private static readonly AttributeSyntax InAttributeSyntax = Attribute(IdentifierName("In"));
        private static readonly AttributeSyntax OutAttributeSyntax = Attribute(IdentifierName("Out"));
        private static readonly AttributeSyntax OptionalAttributeSyntax = Attribute(IdentifierName("Optional"));
        private static readonly AttributeSyntax FlagsAttributeSyntax = Attribute(IdentifierName("Flags"));
        private static readonly AttributeSyntax FieldOffsetAttributeSyntax = Attribute(IdentifierName("FieldOffset"));

        private static readonly SyntaxTokenList PublicModifiers = TokenList(Token(SyntaxKind.PublicKeyword));

        private readonly FileStream metadataStream;
        private readonly PEReader peReader;
        private readonly MetadataReader mr;
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

        private readonly Dictionary<TypeDefinitionHandle, TypeDefinitionHandle> nestedToDeclaringLookup = new Dictionary<TypeDefinitionHandle, TypeDefinitionHandle>();

        internal Generator(string pathToMetaLibrary, LanguageVersion languageVersion = LanguageVersion.CSharp9)
        {
            this.LanguageVersion = languageVersion;
            var project = CSharpCompilation.Create("PInvoke")
                .AddReferences(
                    MetadataReference.CreateFromFile(pathToMetaLibrary, MetadataReferenceProperties.Assembly),
                    MetadataReference.CreateFromFile(typeof(IntPtr).Assembly.Location));

            this.metadataStream = new FileStream(pathToMetaLibrary, FileMode.Open, FileAccess.Read, FileShare.Read);
            this.peReader = new PEReader(this.metadataStream);
            this.mr = this.peReader.GetMetadataReader();

            var workspace = new AdhocWorkspace();
            this.signatureTypeProvider = new SignatureTypeProvider(this);
            this.customAttributeTypeProvider = new CustomAttributeTypeProvider();

            this.Apis = this.mr.TypeDefinitions.Select(this.mr.GetTypeDefinition).Single(td => this.mr.StringComparer.Equals(td.Name, "Apis") && this.mr.StringComparer.Equals(td.Namespace, "Microsoft.Windows.Sdk"));
            this.InitializeNestedToDeclaringLookupDictionary();
        }

        internal CompilationUnitSyntax CompilationUnit
        {
            get => CompilationUnit()
                .AddMembers(this.modulesAndMembers.Select(kv =>
                    ClassDeclaration(Identifier(kv.Key))
                        .AddModifiers(Token(SyntaxKind.PublicKeyword), Token(SyntaxKind.StaticKeyword), Token(SyntaxKind.PartialKeyword))
                        .AddMembers(kv.Value.ToArray())).ToArray())
                        .AddMembers(this.types.Values.ToArray())
                .AddUsings(
                    UsingDirective(IdentifierName(nameof(System))),
                    UsingDirective(ParseName("System.Runtime.InteropServices")))
                .NormalizeWhitespace();
        }

        internal TypeDefinition Apis { get; }

        internal MetadataReader Reader => this.mr;

        internal LanguageVersion LanguageVersion { get; }

        public void Dispose()
        {
            this.peReader.Dispose();
            this.metadataStream.Dispose();
        }

        internal void GenerateAll(CancellationToken cancellationToken)
        {
            this.GenerateAllExternMethods(cancellationToken);

            // Also generate all structs/enum types too, even if not referenced by a method,
            // since some methods use `void*` types and require structs at runtime.
            this.GenerateAllInteropTypes(cancellationToken);
        }

        /// <summary>
        /// Generates a projection of Win32 APIs.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        internal void GenerateAllExternMethods(CancellationToken cancellationToken)
        {
            foreach (MethodDefinitionHandle methodHandle in this.Apis.GetMethods())
            {
                cancellationToken.ThrowIfCancellationRequested();

                var methodDefinition = this.mr.GetMethodDefinition(methodHandle);
                this.GenerateExternMethod(methodDefinition);
            }
        }

        internal void GenerateAllInteropTypes(CancellationToken cancellationToken)
        {
            foreach (TypeDefinitionHandle typeDefinitionHandle in this.mr.TypeDefinitions)
            {
                TypeDefinition typeDef = this.mr.GetTypeDefinition(typeDefinitionHandle);
                if (typeDef.BaseType.IsNil)
                {
                    continue;
                }

                bool isCompilerGenerated = false;
                foreach (CustomAttributeHandle attHandle in typeDef.GetCustomAttributes())
                {
                    var att = this.mr.GetCustomAttribute(attHandle);
                    if (this.IsAttribute(att, "System.Runtime.CompilerServices", nameof(CompilerGeneratedAttribute)))
                    {
                        isCompilerGenerated = true;
                        break;
                    }
                }

                if (isCompilerGenerated)
                {
                    continue;
                }

                this.GenerateInteropType(typeDefinitionHandle);
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

            MethodSignature<TypeSyntax> signature = methodDefinition.DecodeSignature(this.signatureTypeProvider, null);

            var methodName = this.mr.GetString(methodDefinition.Name);
            if (this.IsAnsiFunction(methodDefinition, methodName))
            {
                // Skip Ansi functions.
                return;
            }

            var moduleName = this.GetNormalizedModuleName(import);

            if (false && !CanonicalCapitalizations.Contains(moduleName))
            {
                // Skip methods for modules we are not prepared to export.
                return;
            }

            string? entrypoint = null;
            if (this.IsWideFunction(methodDefinition, methodName))
            {
                entrypoint = methodName;
                methodName = methodName.Substring(0, methodName.Length - 1);
            }

            MethodDeclarationSyntax methodDeclaration = MethodDeclaration(
                List<AttributeListSyntax>().Add(AttributeList().AddAttributes(DllImport(methodDefinition, import, moduleName, entrypoint))),
                modifiers: TokenList(Token(SyntaxKind.PublicKeyword), Token(SyntaxKind.ExternKeyword), Token(SyntaxKind.StaticKeyword)),
                signature.ReturnType,
                explicitInterfaceSpecifier: null!,
                SafeIdentifier(methodName),
                null!,
                this.CreateParameterList(methodDefinition, signature),
                List<TypeParameterConstraintClauseSyntax>(),
                body: null!,
                Token(SyntaxKind.SemicolonToken));
            if (methodDeclaration.ReturnType is PointerTypeSyntax || methodDeclaration.ParameterList.Parameters.Any(p => p.Type is PointerTypeSyntax))
            {
                methodDeclaration = methodDeclaration.AddModifiers(Token(SyntaxKind.UnsafeKeyword));
            }

            List<MemberDeclarationSyntax> methodsList = this.GetModuleMemberList(moduleName);
            methodsList.Add(methodDeclaration);
        }

        internal void GenerateInteropType(TypeDefinitionHandle typeDefHandle)
        {
            if (this.nestedToDeclaringLookup.TryGetValue(typeDefHandle, out TypeDefinitionHandle nestingParentHandle))
            {
                // We should only generate this type into its parent type.
                this.GenerateInteropType(nestingParentHandle);
                return;
            }

            if (!this.typesGenerating.Add(typeDefHandle))
            {
                return;
            }

            MemberDeclarationSyntax? typeDeclaration = this.CreateInteropType(typeDefHandle);

            if (typeDeclaration is object)
            {
                this.types.Add(typeDefHandle, typeDeclaration);
            }
        }

        private static AttributeSyntax FieldOffset(int offset) => FieldOffsetAttributeSyntax.AddArgumentListArguments(AttributeArgument(LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(offset))));

        private static AttributeSyntax StructLayout(TypeDefinition typeDef, TypeLayout layout)
        {
            LayoutKind layoutKind = (typeDef.Attributes & TypeAttributes.ExplicitLayout) == TypeAttributes.ExplicitLayout ? LayoutKind.Explicit : LayoutKind.Sequential;
            var structLayoutAttribute = Attribute(IdentifierName(nameof(StructLayoutAttribute))).AddArgumentListArguments(
                AttributeArgument(MemberAccessExpression(
                    SyntaxKind.SimpleMemberAccessExpression,
                    IdentifierName(nameof(LayoutKind)),
                    IdentifierName(Enum.GetName(typeof(LayoutKind), layoutKind)!))));

            if (layout.PackingSize > 0)
            {
                structLayoutAttribute = structLayoutAttribute.AddArgumentListArguments(
                    AttributeArgument(LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(layout.PackingSize)))
                        .WithNameEquals(NameEquals(nameof(StructLayoutAttribute.Pack))));
            }

            if (layout.Size > 0)
            {
                structLayoutAttribute = structLayoutAttribute.AddArgumentListArguments(
                    AttributeArgument(LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(layout.Size)))
                        .WithNameEquals(NameEquals(nameof(StructLayoutAttribute.Size))));
            }

            return structLayoutAttribute;
        }

        private static AttributeSyntax GUID(Guid guid)
        {
            return Attribute(IdentifierName("Guid")).AddArgumentListArguments(
                AttributeArgument(LiteralExpression(SyntaxKind.StringLiteralExpression, Literal(guid.ToString().ToUpperInvariant()))));
        }

        private static AttributeSyntax DllImport(MethodDefinition methodDefinition, MethodImport import, string moduleName, string? entrypoint)
        {
            var dllImportAttribute = Attribute(IdentifierName("DllImport")).AddArgumentListArguments(
                AttributeArgument(LiteralExpression(SyntaxKind.StringLiteralExpression, Literal(moduleName))),
                AttributeArgument(LiteralExpression(SyntaxKind.TrueLiteralExpression)).WithNameEquals(NameEquals(nameof(DllImportAttribute.ExactSpelling))));

            if (entrypoint is object)
            {
                dllImportAttribute = dllImportAttribute.AddArgumentListArguments(
                    AttributeArgument(LiteralExpression(SyntaxKind.StringLiteralExpression, Literal(entrypoint)))
                        .WithNameEquals(NameEquals(nameof(DllImportAttribute.EntryPoint))));
            }

            return dllImportAttribute;
        }

        private static AttributeSyntax UnmanagedFunctionPointer(CallingConvention callingConvention)
        {
            return Attribute(IdentifierName(nameof(UnmanagedFunctionPointerAttribute)))
                .AddArgumentListArguments(AttributeArgument(MemberAccessExpression(
                    SyntaxKind.SimpleMemberAccessExpression,
                    IdentifierName(nameof(CallingConvention)),
                    IdentifierName(Enum.GetName(typeof(CallingConvention), callingConvention)!))));
        }

        private static SyntaxToken SafeIdentifier(string name) => Identifier(CSharpKeywords.Contains(name) ? "@" + name : name);

        private bool IsWideFunction(MethodDefinition method, string methodName)
        {
            if (methodName.Length > 1 && methodName.EndsWith('W') && char.IsLower(methodName[methodName.Length - 2]))
            {
                // The name looks very much like an Wide-char method.
                // If further confidence is ever needed, we could look at the parameter and return types
                // to see if they have charset-related metadata in their marshaling metadata.
                return true;
            }

            return false;
        }

        private bool IsAnsiFunction(MethodDefinition method, string methodName)
        {
            if (methodName.Length > 1 && methodName.EndsWith('A') && char.IsLower(methodName[methodName.Length - 2]))
            {
                // The name looks very much like an Ansi method.
                // If further confidence is ever needed, we could look at the parameter and return types
                // to see if they have charset-related metadata in their marshaling metadata.
                return true;
            }

            return false;
        }

        private MemberDeclarationSyntax? CreateInteropType(TypeDefinitionHandle typeDefHandle)
        {
            TypeDefinition typeDef = this.mr.GetTypeDefinition(typeDefHandle);
            var baseTypeRef = this.mr.GetTypeReference((TypeReferenceHandle)typeDef.BaseType);
            MemberDeclarationSyntax typeDeclaration;

            if (this.mr.StringComparer.Equals(baseTypeRef.Name, nameof(ValueType)) && this.mr.StringComparer.Equals(baseTypeRef.Namespace, nameof(System)))
            {
                StructDeclarationSyntax structDeclaration = this.CreateInteropStruct(typeDef);

                // Proactively generate all nested types as well.
                foreach (TypeDefinitionHandle nestedHandle in typeDef.GetNestedTypes())
                {
                    if (this.CreateInteropType(nestedHandle) is { } nestedType)
                    {
                        structDeclaration = structDeclaration.AddMembers(nestedType);
                    }
                }

                typeDeclaration = structDeclaration;
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
                // not yet supported.
                return null;
            }

            return typeDeclaration;
        }

        private void InitializeNestedToDeclaringLookupDictionary()
        {
            foreach (TypeDefinitionHandle typeDefHandle in this.mr.TypeDefinitions)
            {
                TypeDefinition typeDefinition = this.mr.GetTypeDefinition(typeDefHandle);
                if (!typeDefinition.IsNested)
                {
                    AddNestedTypesOf(typeDefHandle);
                }
            }

            void AddNestedTypesOf(TypeDefinitionHandle parentHandle)
            {
                TypeDefinition typeDefinition = this.mr.GetTypeDefinition(parentHandle);
                foreach (TypeDefinitionHandle nestedHandle in typeDefinition.GetNestedTypes())
                {
                    if (!nestedHandle.IsNil)
                    {
                        this.nestedToDeclaringLookup.Add(nestedHandle, parentHandle);
                        AddNestedTypesOf(nestedHandle);
                    }
                }
            }
        }

        private DelegateDeclarationSyntax CreateInteropDelegate(TypeDefinition typeDef)
        {
            string name = this.mr.GetString(typeDef.Name);

            CallingConvention? callingConvention = null;
            foreach (CustomAttributeHandle handle in typeDef.GetCustomAttributes())
            {
                var att = this.mr.GetCustomAttribute(handle);
                if (this.IsAttribute(att, "System.Runtime.InteropServices", nameof(UnmanagedFunctionPointerAttribute)))
                {
                    var args = att.DecodeValue(this.customAttributeTypeProvider);
                    callingConvention = (CallingConvention)(int)args.FixedArguments[0].Value!;
                }
            }

            MethodDefinition invokeMethodDef = typeDef.GetMethods().Select(this.mr.GetMethodDefinition).Single(def => this.mr.StringComparer.Equals(def.Name, "Invoke"));
            MethodSignature<TypeSyntax> signature = invokeMethodDef.DecodeSignature(this.signatureTypeProvider, null);

            DelegateDeclarationSyntax result = DelegateDeclaration(signature.ReturnType, name)
                .WithParameterList(this.CreateParameterList(invokeMethodDef, signature))
                .AddModifiers(Token(SyntaxKind.PublicKeyword), Token(SyntaxKind.UnsafeKeyword));

            if (callingConvention.HasValue)
            {
                result = result.AddAttributeLists(AttributeList().AddAttributes(UnmanagedFunctionPointer(callingConvention.Value)));
            }

            return result;
        }

        private StructDeclarationSyntax CreateInteropStruct(TypeDefinition typeDef)
        {
            // TODO: Add handling for
            // * property indexers (e.g. FILE_REGION_OUTPUT._Region_e__FixedBuffer.this[int]
            // * record GuidAttribute
            string name = this.mr.GetString(typeDef.Name);

            var members = new List<MemberDeclarationSyntax>();
            foreach (FieldDefinitionHandle fieldDefHandle in typeDef.GetFields())
            {
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
                VariableDeclaratorSyntax fieldDeclarator = VariableDeclarator(SafeIdentifier(fieldName));
                if (fixedBufferAttribute.HasValue)
                {
                    CustomAttributeValue<TypeSyntax> attributeArgs = fixedBufferAttribute.Value.DecodeValue(this.customAttributeTypeProvider);
                    TypeSyntax fieldType = (TypeSyntax)attributeArgs.FixedArguments[0].Value!;
                    ExpressionSyntax size = LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal((int)attributeArgs.FixedArguments[1].Value!));
                    field = FieldDeclaration(
                        VariableDeclaration(fieldType))
                        .AddDeclarationVariables(
                            fieldDeclarator
                                .WithArgumentList(BracketedArgumentList(SingletonSeparatedList(Argument(size)))))
                        .AddModifiers(Token(SyntaxKind.PublicKeyword), Token(SyntaxKind.UnsafeKeyword), Token(SyntaxKind.FixedKeyword));
                }
                else
                {
                    TypeSyntax fieldType = fieldDef.DecodeSignature(this.signatureTypeProvider, null);
                    fieldType = this.ReinterpretType(fieldType, fieldDef.GetCustomAttributes());
                    field = FieldDeclaration(VariableDeclaration(fieldType).AddVariables(fieldDeclarator))
                        .AddModifiers(Token(SyntaxKind.PublicKeyword));
                    if (fieldType is PointerTypeSyntax)
                    {
                        field = field.AddModifiers(Token(SyntaxKind.UnsafeKeyword));
                    }
                }

                int offset = fieldDef.GetOffset();
                if (offset >= 0)
                {
                    field = field.AddAttributeLists(AttributeList().AddAttributes(FieldOffset(offset)));
                }

                members.Add(field);
            }

            StructDeclarationSyntax result = StructDeclaration(name)
                .AddMembers(members.ToArray())
                .WithModifiers(PublicModifiers);

            TypeLayout layout = typeDef.GetLayout();
            if (!layout.IsDefault)
            {
                result = result.AddAttributeLists(AttributeList().AddAttributes(StructLayout(typeDef, layout)));
            }

            Guid guid = Guid.Empty;
            foreach (CustomAttributeHandle attHandle in typeDef.GetCustomAttributes())
            {
                CustomAttribute att = this.mr.GetCustomAttribute(attHandle);
                if (this.IsAttribute(att, "System.Runtime.InteropServices", nameof(GuidAttribute)))
                {
                    var args = att.DecodeValue(this.customAttributeTypeProvider);
                    guid = Guid.Parse((string)args.FixedArguments[0].Value!);
                }
            }

            if (guid != Guid.Empty)
            {
                result = result.AddAttributeLists(AttributeList().AddAttributes(GUID(guid)));
            }

            return result;
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
                    enumBaseType = fieldDef.DecodeSignature(this.signatureTypeProvider, null);
                    continue;
                }

                Constant value = this.mr.GetConstant(valueHandle);
                enumValues.Add(EnumMemberDeclaration(SafeIdentifier(enumValueName)).WithEqualsValue(EqualsValueClause(this.ToExpressionSyntax(value))));
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
                .AddMembers(enumValues.ToArray())
                .WithModifiers(PublicModifiers);

            if (!(enumBaseType is PredefinedTypeSyntax { Keyword: { RawKind: (int)SyntaxKind.IntKeyword } }))
            {
                result = result.AddBaseListTypes(SimpleBaseType(enumBaseType));
            }

            if (flagsEnum)
            {
                result = result.AddAttributeLists(
                    AttributeList().AddAttributes(FlagsAttributeSyntax));
            }

            return result;
        }

        private bool IsAttribute(CustomAttribute attribute, string ns, string name)
        {
            StringHandle actualNamespace, actualName;
            if (attribute.Constructor.Kind == HandleKind.MemberReference)
            {
                MemberReference memberReference = this.mr.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
                TypeReference parentRef = this.mr.GetTypeReference((TypeReferenceHandle)memberReference.Parent);
                actualNamespace = parentRef.Namespace;
                actualName = parentRef.Name;
            }
            else if (attribute.Constructor.Kind == HandleKind.MethodDefinition)
            {
                MethodDefinition methodDef = this.mr.GetMethodDefinition((MethodDefinitionHandle)attribute.Constructor);
                TypeDefinition typeDef = this.mr.GetTypeDefinition(methodDef.GetDeclaringType());
                actualNamespace = typeDef.Namespace;
                actualName = typeDef.Name;
            }
            else
            {
                throw new NotSupportedException("Unsupported attribute constructor kind: " + attribute.Constructor.Kind);
            }

            return this.mr.StringComparer.Equals(actualName, name) && this.mr.StringComparer.Equals(actualNamespace, ns);
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

        private ParameterListSyntax CreateParameterList(MethodDefinition methodDefinition, MethodSignature<TypeSyntax> signature)
            => ParameterList().AddParameters(methodDefinition.GetParameters().Select(this.mr.GetParameter).Where(p => !p.Name.IsNil).Select(p => this.CreateParameter(signature, p)).ToArray());

        private ParameterSyntax CreateParameter(MethodSignature<TypeSyntax> methodSignature, Parameter parameter)
        {
            string name = this.mr.GetString(parameter.Name);

            // TODO:
            // * change double-pointers to `out` modifiers on single-pointers.
            //   * Consider CredEnumerateA, which is a "pointer to an array of pointers" (3-asterisks!). How does FriendlyAttribute improve this, if at all? The memory must be freed through another p/invoke.
            // * Add [Friendly] attributes
            // * Notice [Out][RIAAFree] handle producing parameters. Can we make these provide SafeHandle's?
            TypeSyntax type = this.ReinterpretType(methodSignature.ParameterTypes[parameter.SequenceNumber - 1], parameter.GetCustomAttributes());

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

                if ((parameter.Attributes & ParameterAttributes.Optional) == ParameterAttributes.Optional)
                {
                    attributes = attributes.AddAttributes(OptionalAttributeSyntax);
                }
            }

            var modifiers = TokenList();

            ParameterSyntax parameterSyntax = Parameter(
                attributes.Attributes.Count > 0 ? List<AttributeListSyntax>().Add(attributes) : List<AttributeListSyntax>(),
                modifiers,
                type,
                SafeIdentifier(name),
                @default: null);

            return parameterSyntax;
        }

        private TypeSyntax ReinterpretType(TypeSyntax originalType, CustomAttributeHandleCollection customAttributes)
        {
            foreach (CustomAttributeHandle attHandle in customAttributes)
            {
                CustomAttribute att = this.mr.GetCustomAttribute(attHandle);
                if (this.IsAttribute(att, "Microsoft.Windows.Sdk", "NativeTypeInfoAttribute"))
                {
                    var args = att.DecodeValue(this.customAttributeTypeProvider);
                    if (args.FixedArguments[0].Value is object value)
                    {
                        UnmanagedType unmanagedType = (UnmanagedType)value;
                        switch (unmanagedType)
                        {
                            case UnmanagedType.Bool: return PredefinedType(Token(SyntaxKind.BoolKeyword));
                            case UnmanagedType.LPWStr:
                                if (originalType is PointerTypeSyntax { ElementType: PredefinedTypeSyntax { Keyword: { RawKind: (int)SyntaxKind.UShortKeyword } } })
                                {
                                    return PointerType(PredefinedType(Token(SyntaxKind.CharKeyword)));
                                }

                                break;

                            case UnmanagedType.LPStr:
                                if (originalType is PointerTypeSyntax { ElementType: PredefinedTypeSyntax { Keyword: { RawKind: (int)SyntaxKind.SByteKeyword } } })
                                {
                                    return PointerType(PredefinedType(Token(SyntaxKind.ByteKeyword)));
                                }

                                break;

                            default:
                                break;
                        }
                    }

                    break;
                }
            }

            return originalType;
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
