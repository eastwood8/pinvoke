// Copyright © .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Win32.CodeGen
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Diagnostics;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Reflection.Metadata;
    using System.Reflection.PortableExecutable;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;
    using System.Xml.Linq;
    using Microsoft.CodeAnalysis;
    using Microsoft.CodeAnalysis.CSharp;
    using Microsoft.CodeAnalysis.CSharp.Syntax;
    using static Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

    public class Generator : IDisposable
    {
        internal static readonly Dictionary<string, TypeSyntax> BclInteropStructs = new Dictionary<string, TypeSyntax>(StringComparer.Ordinal)
        {
            { nameof(System.Runtime.InteropServices.ComTypes.FILETIME), ParseTypeName("System.Runtime.InteropServices.ComTypes.FILETIME") },
        };

        private const string SystemRuntimeCompilerServices = "System.Runtime.CompilerServices";
        private const string SystemRuntimeInteropServices = "System.Runtime.InteropServices";
        private const string MicrosoftWindowsSdk = "Microsoft.Windows.Sdk";
        private const string RIAAFreeAttribute = "RIAAFreeAttribute";
        private const string NativeTypeInfoAttribute = "NativeTypeInfoAttribute";

        private static readonly TypeSyntax SafeHandleTypeSyntax = IdentifierName("SafeHandle");
        private static readonly IdentifierNameSyntax IntPtrTypeSyntax = IdentifierName(nameof(IntPtr));

        /// <summary>
        /// This is the preferred capitalizations for modules and class names.
        /// If they are not in this list, the capitalization will come from the metadata assembly.
        /// </summary>
        private static readonly ImmutableHashSet<string> CanonicalCapitalizations = ImmutableHashSet.Create<string>(
            StringComparer.OrdinalIgnoreCase,
            "AdvApi32",
            "AuthZ",
            "BCrypt",
            "Cabinet",
            "CfgMgr32",
            "Chakra",
            "CodeGeneration",
            "CodeGeneration.Debugging",
            "CodeGenerationAttributes",
            "ComCtl32",
            "ComDlg32",
            "Crypt32",
            "CryptNet",
            "D3D11",
            "D3D12",
            "D3DCompiler_47",
            "DbgHelp",
            "DfsCli",
            "DhcpCSvc",
            "DhcpCSvc6",
            "DnsApi",
            "DsParse",
            "DSRole",
            "DwmApi",
            "DXGI",
            "Esent",
            "FltLib",
            "Fusion",
            "Gdi32",
            "Hid",
            "Icu",
            "ImageHlp",
            "InkObjCore",
            "IPHlpApi",
            "Kernel32",
            "LogonCli",
            "Magnification",
            "MFSensorGroup",
            "Mpr",
            "MSCms",
            "MSCorEE",
            "Msi",
            "MswSock",
            "NCrypt",
            "NetApi32",
            "NetUtils",
            "NewDev",
            "NTDll",
            "Ole32",
            "OleAut32",
            "PowrProf",
            "PropSys",
            "Psapi",
            "RpcRT4",
            "SamCli",
            "SchedCli",
            "SetupApi",
            "SHCore",
            "Shell32",
            "ShlwApi",
            "SrvCli",
            "TokenBinding",
            "UrlMon",
            "User32",
            "UserEnv",
            "UxTheme",
            "Version",
            "WebAuthN",
            "WebServices",
            "WebSocket",
            "Win32",
            "Win32MetaGeneration",
            "Windows.Core",
            "Windows.ShellScalingApi",
            "WinHttp",
            "WinMM",
            "WinUsb",
            "WksCli",
            "WLanApi",
            "WldAp32",
            "WtsApi32");

        private static readonly HashSet<string> CSharpKeywords = new HashSet<string>(StringComparer.Ordinal)
        {
            "object",
            "event",
            "override",
            "public",
            "private",
            "protected",
            "internal",
            "virtual",
            "string",
            "base",
            "ref",
            "in",
            "out",
            "decimal",
        };

        private static readonly HashSet<string> ObjectMembers = new HashSet<string>(StringComparer.Ordinal)
        {
            "GetType",
        };

        private static readonly AttributeSyntax InAttributeSyntax = Attribute(IdentifierName("In"));
        private static readonly AttributeSyntax OutAttributeSyntax = Attribute(IdentifierName("Out"));
        private static readonly AttributeSyntax OptionalAttributeSyntax = Attribute(IdentifierName("Optional"));
        private static readonly AttributeSyntax FlagsAttributeSyntax = Attribute(IdentifierName("Flags"));
        private static readonly AttributeSyntax FieldOffsetAttributeSyntax = Attribute(IdentifierName("FieldOffset"));

        private static readonly SyntaxTokenList PublicModifiers = TokenList(Token(SyntaxKind.PublicKeyword));

        private readonly Stream metadataStream;
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
        /// The set of types that are or have been generated so we don't stack overflow for self-referencing types.
        /// </summary>
        private readonly HashSet<TypeDefinitionHandle> typesGenerating = new HashSet<TypeDefinitionHandle>();

        /// <summary>
        /// The set of methods that are or have been generated.
        /// </summary>
        private readonly HashSet<MethodDefinitionHandle> methodsGenerating = new HashSet<MethodDefinitionHandle>();

        private readonly Dictionary<TypeDefinitionHandle, TypeDefinitionHandle> nestedToDeclaringLookup = new Dictionary<TypeDefinitionHandle, TypeDefinitionHandle>();

        private readonly Dictionary<string, MethodDefinitionHandle> methodsByName;

        private readonly Dictionary<string, TypeSyntax?> releaseMethodsWithSafeHandleTypesGenerating = new Dictionary<string, TypeSyntax?>();

        public Generator()
        {
            Stream? metadataLibraryStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Win32.CodeGen.Win32MetadataLib.dll");
            if (metadataLibraryStream is null)
            {
                throw new Exception("Metadata assembly not found.");
            }

            this.metadataStream = metadataLibraryStream;
            this.peReader = new PEReader(this.metadataStream);
            this.mr = this.peReader.GetMetadataReader();

            this.signatureTypeProvider = new SignatureTypeProvider(this);
            this.customAttributeTypeProvider = new CustomAttributeTypeProvider();

            this.Apis = this.mr.TypeDefinitions.Select(this.mr.GetTypeDefinition).Single(td => this.mr.StringComparer.Equals(td.Name, "Apis") && this.mr.StringComparer.Equals(td.Namespace, MicrosoftWindowsSdk));
            this.InitializeNestedToDeclaringLookupDictionary();
            this.methodsByName = this.Apis.GetMethods().ToDictionary(h => this.mr.GetString(this.mr.GetMethodDefinition(h).Name), StringComparer.Ordinal);
        }

        public CompilationUnitSyntax CompilationUnit
        {
            get => CompilationUnit()
                .AddMembers(
                    NamespaceDeclaration(ParseName(this.Namespace))
                        .AddMembers(this.MembersByClass.Select(kv =>
                            ClassDeclaration(Identifier(GetClassNameForModule(kv.Key)))
                                .AddModifiers(Token(SyntaxKind.PublicKeyword), Token(SyntaxKind.StaticKeyword), Token(SyntaxKind.PartialKeyword))
                                .AddMembers(kv.ToArray())).ToArray())
                                .AddMembers(this.types.Values.ToArray())
                        .AddUsings(
                            UsingDirective(IdentifierName(nameof(System))),
                            UsingDirective(IdentifierName(nameof(System) + "." + nameof(System.Diagnostics))),
                            UsingDirective(ParseName(SystemRuntimeInteropServices))))
                .WithLeadingTrivia(TriviaList(
                    Trivia(PragmaWarningDirectiveTrivia(Token(SyntaxKind.DisableKeyword), true).WithErrorCodes(SingletonSeparatedList<ExpressionSyntax>(IdentifierName("CS1591"))))))
                .NormalizeWhitespace();
        }

        public bool WideCharOnly { get; set; } = true;

        internal TypeDefinition Apis { get; }

        internal MetadataReader Reader => this.mr;

        internal LanguageVersion LanguageVersion { get; set; } = LanguageVersion.CSharp9;

        internal string Namespace { get; set; } = "PInvoke.Windows";

        private IEnumerable<IGrouping<string, MemberDeclarationSyntax>> MembersByClass =>
            from entry in this.modulesAndMembers
            from method in entry.Value
            group method by GetClassNameForModule(entry.Key) into x
            select x;

        public void Dispose()
        {
            this.peReader.Dispose();
            this.metadataStream.Dispose();
        }

        public void GenerateAll(CancellationToken cancellationToken)
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
        public void GenerateAllExternMethods(CancellationToken cancellationToken)
        {
            foreach (MethodDefinitionHandle methodHandle in this.Apis.GetMethods())
            {
                cancellationToken.ThrowIfCancellationRequested();

                this.GenerateExternMethod(methodHandle);
            }
        }

        public bool TryGenerateAllExternMethods(string moduleName, CancellationToken cancellationToken)
        {
            bool successful = false;
            foreach (MethodDefinitionHandle methodHandle in this.Apis.GetMethods())
            {
                cancellationToken.ThrowIfCancellationRequested();

                MethodDefinition methodDef = this.mr.GetMethodDefinition(methodHandle);
                ModuleReferenceHandle moduleHandle = methodDef.GetImport().Module;
                if (moduleHandle.IsNil)
                {
                    continue;
                }

                ModuleReference module = this.mr.GetModuleReference(moduleHandle);
                if (this.mr.StringComparer.Equals(module.Name, moduleName, ignoreCase: true))
                {
                    this.GenerateExternMethod(methodHandle);
                    successful = true;
                }
            }

            return successful;
        }

        public bool TryGenerateExternMethod(string name)
        {
            if (this.methodsByName.TryGetValue(name, out MethodDefinitionHandle handle))
            {
                this.GenerateExternMethod(handle);
                return true;
            }

            bool successful = false;
            if (this.methodsByName.TryGetValue(name + "W", out handle))
            {
                this.GenerateExternMethod(handle);
                successful = true;
            }

            if (this.methodsByName.TryGetValue(name + "A", out handle))
            {
                this.GenerateExternMethod(handle);
                successful = true;
            }

            return successful;
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

                this.GenerateInteropType(typeDefinitionHandle);
            }
        }

        internal void GenerateExternMethod(MethodDefinitionHandle methodDefinitionHandle)
        {
            if (methodDefinitionHandle.IsNil)
            {
                return;
            }

            if (!this.methodsGenerating.Add(methodDefinitionHandle))
            {
                return;
            }

            MethodDefinition methodDefinition = this.mr.GetMethodDefinition(methodDefinitionHandle);
            MethodImport import = methodDefinition.GetImport();
            if (import.Name.IsNil)
            {
                // Not an exported method.
                return;
            }

            MethodSignature<TypeSyntax> signature = methodDefinition.DecodeSignature(this.signatureTypeProvider, null);

            var methodName = this.mr.GetString(methodDefinition.Name);
            if (this.WideCharOnly && this.IsAnsiFunction(methodName))
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
            if (this.TryGetRenamedMethod(methodName, out string? newName))
            {
                entrypoint = methodName;
                methodName = newName;
            }

            CustomAttributeHandleCollection? returnTypeAttributes = this.GetReturnTypeCustomAttributes(methodDefinition);

            TypeSyntax returnType = signature.ReturnType;
            AttributeSyntax? returnTypeAttribute = null;
            if (returnTypeAttributes.HasValue)
            {
                (returnType, returnTypeAttribute) = this.ReinterpretMethodSignatureType(signature.ReturnType, returnTypeAttributes.Value);
            }

            MethodDeclarationSyntax methodDeclaration = MethodDeclaration(
                List<AttributeListSyntax>().Add(AttributeList().AddAttributes(DllImport(methodDefinition, import, moduleName, entrypoint))),
                modifiers: TokenList(Token(SyntaxKind.PublicKeyword), Token(SyntaxKind.ExternKeyword), Token(SyntaxKind.StaticKeyword)),
                returnType,
                explicitInterfaceSpecifier: null!,
                SafeIdentifier(methodName),
                null!,
                this.CreateParameterList(methodDefinition, signature),
                List<TypeParameterConstraintClauseSyntax>(),
                body: null!,
                Token(SyntaxKind.SemicolonToken));
            if (returnTypeAttribute is object)
            {
                methodDeclaration = methodDeclaration.AddAttributeLists(
                    AttributeList().WithTarget(AttributeTargetSpecifier(Token(SyntaxKind.ReturnKeyword))).AddAttributes(returnTypeAttribute));
            }

            // Add documentation if we can find it.
            methodDeclaration = AddApiDocumentation(entrypoint ?? methodName, methodDeclaration);

            List<MemberDeclarationSyntax> methodsList = this.GetModuleMemberList(moduleName);
            if (methodDeclaration.ReturnType is PointerTypeSyntax || methodDeclaration.ParameterList.Parameters.Any(p => p.Type is PointerTypeSyntax))
            {
                methodDeclaration = methodDeclaration.AddModifiers(Token(SyntaxKind.UnsafeKeyword));
                methodsList.AddRange(this.CreateFriendlyOverloads(methodDefinition, methodDeclaration, GetClassNameForModule(moduleName)));
            }

            methodsList.Add(methodDeclaration);

            // If RIAAFree applies, make sure we generate the close handle method.
            if (returnTypeAttributes.HasValue)
            {
                foreach (CustomAttributeHandle attHandle in returnTypeAttributes)
                {
                    CustomAttribute att = this.mr.GetCustomAttribute(attHandle);
                    if (this.IsAttribute(att, MicrosoftWindowsSdk, RIAAFreeAttribute))
                    {
                        var args = att.DecodeValue(this.customAttributeTypeProvider);
                        if (args.FixedArguments[0].Value is string freeMethodName)
                        {
                            this.TryGenerateExternMethod(freeMethodName);
                        }

                        break;
                    }
                }
            }
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

        private static T AddApiDocumentation<T>(string api, T memberDeclaration)
            where T : MemberDeclarationSyntax
        {
            if (Docs.Instance.TryGetApiDocs(api, out var docs))
            {
                var docCommentsBuilder = new StringBuilder();
                docCommentsBuilder.AppendLine($@"/// <summary>
/// {new XText(docs.Description)}
/// </summary>");
                if (docs.Parameters is object)
                {
                    foreach (var entry in docs.Parameters)
                    {
                        docCommentsBuilder.Append($@"/// <param name=""{entry.Key}"">");
                        EmitDoc(entry.Value, docCommentsBuilder, docs, "parameters");
                        docCommentsBuilder.AppendLine("</param>");
                    }
                }

                if (docs.ReturnValue is object)
                {
                    docCommentsBuilder.Append("/// <returns>");
                    EmitDoc(docs.ReturnValue, docCommentsBuilder, docs, "return-value");
                    docCommentsBuilder.AppendLine("</returns>");
                }

                docCommentsBuilder.AppendLine($@"/// <remarks>
/// <see href=""{docs.HelpLink}"">Learn more about this API from docs.microsoft.com</see>.
/// </remarks>");
                memberDeclaration = memberDeclaration.WithLeadingTrivia(
                    ParseLeadingTrivia(docCommentsBuilder.ToString()));
            }

            return memberDeclaration;

            static void EmitDoc(string paramDoc, StringBuilder docCommentsBuilder, Docs.ApiDetails docs, string docsAnchor)
            {
                if (paramDoc.Contains('\n'))
                {
                    docCommentsBuilder.AppendLine();
                    var docReader = new StringReader(paramDoc);
                    string? paramDocLine;

                    while ((paramDocLine = docReader.ReadLine()) is object)
                    {
                        docCommentsBuilder.Append("/// ");
                        docCommentsBuilder.AppendLine(new XText(paramDocLine).ToString());
                        break; // just read the first line for now till we can clean up what can come later.
                    }

                    docCommentsBuilder.AppendLine($@"/// <para>This doc was truncated. <see href=""{docs.HelpLink}#{docsAnchor}"">Read the rest on docs.microsoft.com</see>.</para>");
                    docCommentsBuilder.Append("/// ");
                }
                else
                {
                    docCommentsBuilder.Append(paramDoc);
                }
            }
        }

        private static string GetClassNameForModule(string moduleName) =>
            moduleName.StartsWith("api-") || moduleName.StartsWith("ext-") ? "ApiSets" : moduleName.Replace('-', '_');

        private static AttributeSyntax FieldOffset(int offset) => FieldOffsetAttributeSyntax.AddArgumentListArguments(AttributeArgument(LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(offset))));

        private static AttributeSyntax StructLayout(TypeDefinition typeDef, TypeLayout layout)
        {
            LayoutKind layoutKind = (typeDef.Attributes & TypeAttributes.ExplicitLayout) == TypeAttributes.ExplicitLayout ? LayoutKind.Explicit : LayoutKind.Sequential;
            var structLayoutAttribute = Attribute(IdentifierName("StructLayout")).AddArgumentListArguments(
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

            if ((import.Attributes & MethodImportAttributes.SetLastError) == MethodImportAttributes.SetLastError)
            {
                dllImportAttribute = dllImportAttribute.AddArgumentListArguments(
                    AttributeArgument(LiteralExpression(SyntaxKind.TrueLiteralExpression))
                        .WithNameEquals(NameEquals(nameof(DllImportAttribute.SetLastError))));
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

        private static AttributeSyntax MarshalAs(UnmanagedType unmanagedType)
        {
            return Attribute(IdentifierName("MarshalAs"))
                .AddArgumentListArguments(AttributeArgument(
                    MemberAccessExpression(
                        SyntaxKind.SimpleMemberAccessExpression,
                        IdentifierName(nameof(UnmanagedType)),
                        IdentifierName(Enum.GetName(typeof(UnmanagedType), unmanagedType)!))));
        }

        private static AttributeSyntax DebuggerBrowsable(DebuggerBrowsableState state)
        {
            return Attribute(IdentifierName("DebuggerBrowsable"))
                .AddArgumentListArguments(
                AttributeArgument(MemberAccessExpression(
                    SyntaxKind.SimpleMemberAccessExpression,
                    IdentifierName(nameof(DebuggerBrowsableState)),
                    IdentifierName(Enum.GetName(typeof(DebuggerBrowsableState), state)!))));
        }

        private static SyntaxToken SafeIdentifier(string name) => Identifier(CSharpKeywords.Contains(name) ? "@" + name : name);

        private static string GetHiddenFieldName(string fieldName) => $"__{fieldName}";

        private static CrefParameterListSyntax ToCref(ParameterListSyntax parameterList) => CrefParameterList().AddParameters(parameterList.Parameters.Select(ToCref).ToArray());

        private static CrefParameterSyntax ToCref(ParameterSyntax parameter)
            => CrefParameter(
                parameter.Modifiers.Any(SyntaxKind.RefKeyword) ? Token(SyntaxKind.RefKeyword) :
                parameter.Modifiers.Any(SyntaxKind.OutKeyword) ? Token(SyntaxKind.OutKeyword) :
                default,
                parameter.Type!);

        private bool TryGetRenamedMethod(string methodName, [NotNullWhen(true)] out string? newName)
        {
            if (this.WideCharOnly && this.IsWideFunction(methodName))
            {
                newName = methodName.Substring(0, methodName.Length - 1);
                return !this.methodsByName.ContainsKey(newName);
            }

            newName = null;
            return false;
        }

        private CustomAttributeHandleCollection? GetReturnTypeCustomAttributes(MethodDefinition methodDefinition)
        {
            CustomAttributeHandleCollection? returnTypeAttributes = null;
            foreach (ParameterHandle parameterHandle in methodDefinition.GetParameters())
            {
                var parameter = this.mr.GetParameter(parameterHandle);
                if (parameter.Name.IsNil)
                {
                    returnTypeAttributes = parameter.GetCustomAttributes();
                }

                // What we're looking for would always be the first element in the collection.
                break;
            }

            return returnTypeAttributes;
        }

        private bool IsCompilerGenerated(TypeDefinition typeDef)
        {
            bool isCompilerGenerated = false;
            foreach (CustomAttributeHandle attHandle in typeDef.GetCustomAttributes())
            {
                var att = this.mr.GetCustomAttribute(attHandle);
                if (this.IsAttribute(att, SystemRuntimeCompilerServices, nameof(CompilerGeneratedAttribute)))
                {
                    isCompilerGenerated = true;
                    break;
                }
            }

            return isCompilerGenerated;
        }

        private TypeSyntax? GenerateSafeHandle(string releaseMethod)
        {
            if (this.releaseMethodsWithSafeHandleTypesGenerating.TryGetValue(releaseMethod, out TypeSyntax? safeHandleType))
            {
                return safeHandleType;
            }

            MethodDefinitionHandle releaseMethodHandle = this.methodsByName[releaseMethod];
            MethodDefinition releaseMethodDef = this.mr.GetMethodDefinition(releaseMethodHandle);
            string releaseMethodModule = this.GetNormalizedModuleName(releaseMethodDef.GetImport());
            var releaseMethodSignature = releaseMethodDef.DecodeSignature(this.signatureTypeProvider, null);
            TypeSyntax releaseMethodReturnType = this.GetReturnTypeCustomAttributes(releaseMethodDef) is { } atts
                ? this.ReinterpretMethodSignatureType(releaseMethodSignature.ReturnType, atts).Type
                : releaseMethodSignature.ReturnType;

            // If the release method takes more than one parameter, we can't generate a SafeHandle for it.
            if (releaseMethodSignature.RequiredParameterCount != 1)
            {
                return null;
            }

            // TODO: Reuse existing SafeHandle's defined in .NET where possible to facilitate interop with APIs that take them.
            string safeHandleClassName = $"{releaseMethod}SafeHandle";
            this.TryGetRenamedMethod(releaseMethod, out string? renamedReleaseMethod);

            var members = new List<MemberDeclarationSyntax>();

            MemberAccessExpressionSyntax thisHandle = MemberAccessExpression(SyntaxKind.SimpleMemberAccessExpression, ThisExpression(), IdentifierName("handle"));
            ExpressionSyntax intptrZero = DefaultExpression(IntPtrTypeSyntax);
            ExpressionSyntax intptrMinusOne = ObjectCreationExpression(IntPtrTypeSyntax).AddArgumentListArguments(Argument(LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(-1))));

            // private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
            const string invalidValueFieldName = "INVALID_HANDLE_VALUE";
            members.Add(FieldDeclaration(VariableDeclaration(IntPtrTypeSyntax).AddVariables(
                VariableDeclarator(invalidValueFieldName).WithInitializer(EqualsValueClause(intptrMinusOne))))
                .AddModifiers(Token(SyntaxKind.PrivateKeyword), Token(SyntaxKind.StaticKeyword), Token(SyntaxKind.ReadOnlyKeyword)));

            // public SafeHandle() : base(INVALID_HANDLE_VALUE, true)
            members.Add(ConstructorDeclaration(safeHandleClassName)
                .WithInitializer(ConstructorInitializer(SyntaxKind.BaseConstructorInitializer, ArgumentList().AddArguments(
                    Argument(IdentifierName(invalidValueFieldName)),
                    Argument(LiteralExpression(SyntaxKind.TrueLiteralExpression)))))
                .WithBody(Block()));

            // public SafeHandle(IntPtr preexistingHandle, bool ownsHandle = true) : base(INVALID_HANDLE_VALUE, ownsHandle) { this.SetHandle(preexistingHandle); }
            const string preexistingHandleName = "preexistingHandle";
            const string ownsHandleName = "ownsHandle";
            members.Add(ConstructorDeclaration(safeHandleClassName)
                .AddParameterListParameters(
                    Parameter(Identifier(preexistingHandleName)).WithType(IntPtrTypeSyntax),
                    Parameter(Identifier(ownsHandleName)).WithType(PredefinedType(Token(SyntaxKind.BoolKeyword)))
                        .WithDefault(EqualsValueClause(LiteralExpression(SyntaxKind.TrueLiteralExpression))))
                .WithInitializer(ConstructorInitializer(SyntaxKind.BaseConstructorInitializer, ArgumentList().AddArguments(
                    Argument(IdentifierName(invalidValueFieldName)),
                    Argument(IdentifierName(ownsHandleName)))))
                .WithBody(Block().AddStatements(
                    ExpressionStatement(InvocationExpression(MemberAccessExpression(
                        SyntaxKind.SimpleMemberAccessExpression,
                        ThisExpression(),
                        IdentifierName("SetHandle"))).AddArgumentListArguments(
                        Argument(IdentifierName(preexistingHandleName)))))));

            // public override bool IsInvalid => this.handle == default || this.Handle == INVALID_HANDLE_VALUE;
            members.Add(PropertyDeclaration(PredefinedType(Token(SyntaxKind.BoolKeyword)), nameof(SafeHandle.IsInvalid))
                .AddModifiers(Token(SyntaxKind.PublicKeyword), Token(SyntaxKind.OverrideKeyword))
                .WithExpressionBody(ArrowExpressionClause(
                    BinaryExpression(
                        SyntaxKind.LogicalOrExpression,
                        BinaryExpression(SyntaxKind.EqualsExpression, thisHandle, intptrZero),
                        BinaryExpression(SyntaxKind.EqualsExpression, thisHandle, IdentifierName(invalidValueFieldName)))))
                .WithSemicolonToken(Token(SyntaxKind.SemicolonToken)));

            // protected override bool ReleaseHandle() => ReleaseMethod(this.handle);
            // Special case release functions based on their return type as follows: (https://github.com/microsoft/win32metadata/issues/25)
            //  * bool => true is success
            //  * int => zero is success
            //  * uint => zero is success
            //  * byte => non-zero is success
            ExpressionSyntax releaseInvocation = InvocationExpression(
                MemberAccessExpression(SyntaxKind.SimpleMemberAccessExpression, IdentifierName(releaseMethodModule), IdentifierName(renamedReleaseMethod ?? releaseMethod)),
                ArgumentList().AddArguments(Argument(thisHandle)));
            BlockSyntax? releaseBlock = null;
            if (!(releaseMethodReturnType is PredefinedTypeSyntax { Keyword: { RawKind: (int)SyntaxKind.BoolKeyword } }))
            {
                SyntaxKind returnType = ((PredefinedTypeSyntax)releaseMethodReturnType).Keyword.Kind();
                if (returnType == SyntaxKind.IntKeyword)
                {
                    releaseInvocation = BinaryExpression(SyntaxKind.EqualsExpression, releaseInvocation, LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(0)));
                }
                else
                if (returnType == SyntaxKind.UIntKeyword)
                {
                    releaseInvocation = BinaryExpression(SyntaxKind.EqualsExpression, releaseInvocation, LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(0)));
                }
                else if (returnType == SyntaxKind.ByteKeyword)
                {
                    releaseInvocation = BinaryExpression(SyntaxKind.NotEqualsExpression, releaseInvocation, LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(0)));
                }
                else if (returnType == SyntaxKind.VoidKeyword)
                {
                    releaseBlock = Block(
                        ExpressionStatement(releaseInvocation),
                        ReturnStatement(LiteralExpression(SyntaxKind.TrueLiteralExpression)));
                }
                else
                {
                    throw new NotSupportedException($"Return type {returnType} on release method {releaseMethod} not supported.");
                }
            }

            MethodDeclarationSyntax releaseHandleDeclaration = MethodDeclaration(PredefinedType(Token(SyntaxKind.BoolKeyword)), "ReleaseHandle")
                .AddModifiers(Token(SyntaxKind.ProtectedKeyword), Token(SyntaxKind.OverrideKeyword));
            releaseHandleDeclaration = releaseBlock is null
                ? releaseHandleDeclaration
                     .WithExpressionBody(ArrowExpressionClause(releaseInvocation))
                     .WithSemicolonToken(Token(SyntaxKind.SemicolonToken))
                : releaseHandleDeclaration
                    .WithBody(releaseBlock);
            members.Add(releaseHandleDeclaration);

            ClassDeclarationSyntax safeHandleDeclaration = ClassDeclaration(safeHandleClassName)
                .AddModifiers(Token(SyntaxKind.PublicKeyword))
                .AddBaseListTypes(SimpleBaseType(SafeHandleTypeSyntax))
                .AddMembers(members.ToArray())
                .WithLeadingTrivia(ParseLeadingTrivia($@"/// <summary>
        /// Represents a Win32 handle that can be closed with <see cref=""{releaseMethodModule}.{renamedReleaseMethod ?? releaseMethod}""/>.
        /// </summary>
"));

            this.GetModuleMemberList(releaseMethodModule).Add(safeHandleDeclaration);

            safeHandleType = QualifiedName(IdentifierName(releaseMethodModule), IdentifierName(safeHandleDeclaration.Identifier));
            this.releaseMethodsWithSafeHandleTypesGenerating.Add(releaseMethod, safeHandleType);
            return safeHandleType;
        }

        private bool IsWideFunction(string methodName)
        {
            if (methodName.Length > 1 && methodName.EndsWith("W") && char.IsLower(methodName[methodName.Length - 2]))
            {
                // The name looks very much like an Wide-char method.
                // If further confidence is ever needed, we could look at the parameter and return types
                // to see if they have charset-related metadata in their marshaling metadata.
                return true;
            }

            return false;
        }

        private bool IsAnsiFunction(string methodName)
        {
            if (methodName.Length > 1 && methodName.EndsWith("A") && char.IsLower(methodName[methodName.Length - 2]))
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
            if (this.IsCompilerGenerated(typeDef))
            {
                return null;
            }

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
                // TODO: reuse .NET types like FileAccess
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
                if (this.IsAttribute(att, SystemRuntimeInteropServices, nameof(UnmanagedFunctionPointerAttribute)))
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
                    if (this.IsAttribute(att, SystemRuntimeCompilerServices, nameof(FixedBufferAttribute)))
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
                    var fieldInfo = this.ReinterpretFieldType(fieldDeclarator.Identifier.ValueText, fieldDef.DecodeSignature(this.signatureTypeProvider, null), fieldDef.GetCustomAttributes());
                    if (fieldInfo.Property is object)
                    {
                        fieldDeclarator = fieldDeclarator.WithIdentifier(Identifier(GetHiddenFieldName(fieldDeclarator.Identifier.ValueText)));

                        members.Add(fieldInfo.Property);
                    }

                    field = FieldDeclaration(VariableDeclaration(fieldInfo.FieldType).AddVariables(fieldDeclarator))
                        .AddModifiers(Token(fieldInfo.Property is object ? SyntaxKind.PrivateKeyword : SyntaxKind.PublicKeyword));

                    if (fieldInfo.Property is object)
                    {
                        field = field.AddAttributeLists(AttributeList().AddAttributes(DebuggerBrowsable(DebuggerBrowsableState.Never)));
                    }

                    if (fieldInfo.FieldType is PointerTypeSyntax)
                    {
                        field = field.AddModifiers(Token(SyntaxKind.UnsafeKeyword));
                    }

                    if (ObjectMembers.Contains(fieldName))
                    {
                        field = field.AddModifiers(Token(SyntaxKind.NewKeyword));
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
            if (!layout.IsDefault || (typeDef.Attributes & TypeAttributes.ExplicitLayout) == TypeAttributes.ExplicitLayout)
            {
                result = result.AddAttributeLists(AttributeList().AddAttributes(StructLayout(typeDef, layout)));
            }

            Guid guid = Guid.Empty;
            foreach (CustomAttributeHandle attHandle in typeDef.GetCustomAttributes())
            {
                CustomAttribute att = this.mr.GetCustomAttribute(attHandle);
                if (this.IsAttribute(att, SystemRuntimeInteropServices, nameof(GuidAttribute)))
                {
                    var args = att.DecodeValue(this.customAttributeTypeProvider);
                    guid = Guid.Parse((string)args.FixedArguments[0].Value!);
                }
            }

            if (guid != Guid.Empty)
            {
                result = result.AddAttributeLists(AttributeList().AddAttributes(GUID(guid)));
            }

            result = AddApiDocumentation(name, result);

            return result;
        }

        private EnumDeclarationSyntax CreateInteropEnum(TypeDefinition typeDef)
        {
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

            var enumValues = new List<SyntaxNodeOrToken>();
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
                ExpressionSyntax enumValue = flagsEnum ? this.ToHexExpressionSyntax(value) : this.ToExpressionSyntax(value);
                EnumMemberDeclarationSyntax enumMember = EnumMemberDeclaration(SafeIdentifier(enumValueName))
                    .WithEqualsValue(EqualsValueClause(enumValue));
                enumValues.Add(enumMember);
                enumValues.Add(Token(SyntaxKind.CommaToken));
            }

            if (enumBaseType is null)
            {
                throw new NotSupportedException("Unknown enum type.");
            }

            var name = this.mr.GetString(typeDef.Name);
            EnumDeclarationSyntax result = EnumDeclaration(name)
                .WithMembers(SeparatedList<EnumMemberDeclarationSyntax>(enumValues.ToArray()))
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

            result = AddApiDocumentation(name, result);

            return result;
        }

        private IEnumerable<MethodDeclarationSyntax> CreateFriendlyOverloads(MethodDefinition methodDefinition, MethodDeclarationSyntax externMethodDeclaration, string declaringTypeName)
        {
            static ParameterSyntax StripAttributes(ParameterSyntax parameter) => parameter.WithAttributeLists(List<AttributeListSyntax>());
            static TypeSyntax MakeSpanOfT(TypeSyntax typeArgument) => QualifiedName(IdentifierName("System"), GenericName(Identifier("Span")).AddTypeArgumentListArguments(typeArgument));
            static TypeSyntax MakeReadOnlySpanOfT(TypeSyntax typeArgument) => QualifiedName(IdentifierName("System"), GenericName(Identifier("ReadOnlySpan")).AddTypeArgumentListArguments(typeArgument));

            var parameters = externMethodDeclaration.ParameterList.Parameters.Select(StripAttributes).ToList();
            var arguments = externMethodDeclaration.ParameterList.Parameters.Select(p => Argument(IdentifierName(p.Identifier.Text))).ToList();
            var fixedBlocks = new List<VariableDeclarationSyntax>();
            var leadingStatements = new List<StatementSyntax>();
            bool signatureChanged = false;
            foreach (ParameterHandle paramHandle in methodDefinition.GetParameters())
            {
                var param = this.mr.GetParameter(paramHandle);
                if (param.SequenceNumber == 0)
                {
                    continue;
                }

                // TODO:
                // * Review double/triple pointer scenarios.
                // * Review pointers to COM pointer scenarios.
                // * Add nullable annotations on COM interfaces that are annotated as optional.
                // * Create an overload with fewer parameters when one parameter describes the length of another.
                if (parameters[param.SequenceNumber - 1].Type is PointerTypeSyntax ptrType
                    && !(ptrType.ElementType is PredefinedTypeSyntax { Keyword: { RawKind: (int)SyntaxKind.VoidKeyword } }))
                {
                    bool isPointerToPointer = ptrType.ElementType is PointerTypeSyntax;
                    bool isOptional = (param.Attributes & ParameterAttributes.Optional) == ParameterAttributes.Optional;
                    bool isIn = (param.Attributes & ParameterAttributes.In) == ParameterAttributes.In;
                    bool isOut = (param.Attributes & ParameterAttributes.Out) == ParameterAttributes.Out;

                    // If there are no SAL annotations at all, assume it is bidirectional.
                    if (!isOptional && !isIn && !isOut)
                    {
                        isIn = isOut = true;
                    }

                    bool isConst = false;
                    bool isArray = false;
                    UnmanagedType? unmanagedType = null;
                    bool isNullTerminated = false;
                    short? sizeParamIndex = null;
                    foreach (CustomAttributeHandle attHandle in param.GetCustomAttributes())
                    {
                        CustomAttribute att = this.mr.GetCustomAttribute(attHandle);
                        if (this.IsAttribute(att, MicrosoftWindowsSdk, "ConstAttribute"))
                        {
                            isConst = true;
                            continue;
                        }

                        if (this.IsAttribute(att, MicrosoftWindowsSdk, NativeTypeInfoAttribute))
                        {
                            var args = att.DecodeValue(this.customAttributeTypeProvider);
                            if (args.FixedArguments[0].Value is object value)
                            {
                                unmanagedType = (UnmanagedType)value;
                                switch (unmanagedType.Value)
                                {
                                    case UnmanagedType.LPWStr:
                                        isArray = true;
                                        break;
                                }
                            }

                            isNullTerminated |= args.NamedArguments.Any(a => a.Name == "IsNullTerminated" && a.Value is bool value && value);
                            sizeParamIndex = (short?)args.NamedArguments.FirstOrDefault(a => a.Name == "SizeParamIndex").Value;

                            continue;
                        }
                    }

                    IdentifierNameSyntax origName = IdentifierName(parameters[param.SequenceNumber - 1].Identifier.ValueText);
                    IdentifierNameSyntax localName = IdentifierName(origName + "Local");
                    if (isArray)
                    {
                        signatureChanged = true;
                        parameters[param.SequenceNumber - 1] = parameters[param.SequenceNumber - 1]
                            .WithType(isIn && isConst ? MakeReadOnlySpanOfT(ptrType.ElementType) : MakeSpanOfT(ptrType.ElementType));
                        fixedBlocks.Add(VariableDeclaration(ptrType).AddVariables(
                            VariableDeclarator(localName.Identifier).WithInitializer(EqualsValueClause(origName))));
                        arguments[param.SequenceNumber - 1] = Argument(localName);

                        if (isNullTerminated && !sizeParamIndex.HasValue)
                        {
                            // In an abundance of caution, since in .NET a Span type carries length information which
                            // does not propagate to the native side, make sure that the span's last element is \0 (or perhaps
                            // the element after that).
                            // In reading beyond the last element, maybe we'll trigger an AV, but better us than the operating system
                            // to notify the caller when they forgot to add a null terminator.
                            //// if ((param.Length == 0 || param[param.Length - 1] != default) && *(paramLocal + param.Length) != default)
                            ////    throw new ArgumentException("Null termination required.", nameof(param));
                            ExpressionSyntax paramLength = MemberAccessExpression(SyntaxKind.SimpleMemberAccessExpression, origName, IdentifierName(nameof(Span<int>.Length)));
                            leadingStatements.Add(
                                IfStatement(
                                    BinaryExpression(
                                        SyntaxKind.LogicalAndExpression,
                                        ParenthesizedExpression(
                                            BinaryExpression(
                                                SyntaxKind.LogicalOrExpression,
                                                BinaryExpression(SyntaxKind.EqualsExpression, paramLength, LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(0))),
                                                BinaryExpression(
                                                    SyntaxKind.NotEqualsExpression,
                                                    ElementAccessExpression(origName).AddArgumentListArguments(
                                                        Argument(BinaryExpression(SyntaxKind.SubtractExpression, paramLength, LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(1))))),
                                                    LiteralExpression(SyntaxKind.DefaultLiteralExpression)))),
                                        BinaryExpression(
                                            SyntaxKind.NotEqualsExpression,
                                            PrefixUnaryExpression(
                                                SyntaxKind.PointerIndirectionExpression,
                                                ParenthesizedExpression(BinaryExpression(
                                                    SyntaxKind.AddExpression,
                                                    localName,
                                                    paramLength))),
                                            LiteralExpression(SyntaxKind.DefaultLiteralExpression))),
                                    ThrowStatement(ObjectCreationExpression(IdentifierName(nameof(ArgumentException)))
                                        .AddArgumentListArguments(
                                            Argument(LiteralExpression(SyntaxKind.StringLiteralExpression, Literal("Null termination required."))),
                                            Argument(InvocationExpression(IdentifierName("nameof")).AddArgumentListArguments(Argument(origName)))))));
                        }
                    }
                    else if (isIn && isOptional && !isOut && !isPointerToPointer)
                    {
                        signatureChanged = true;
                        parameters[param.SequenceNumber - 1] = parameters[param.SequenceNumber - 1]
                            .WithType(NullableType(ptrType.ElementType));
                        leadingStatements.Add(
                            LocalDeclarationStatement(VariableDeclaration(ptrType.ElementType)
                                .AddVariables(VariableDeclarator(localName.Identifier).WithInitializer(
                                    EqualsValueClause(ConditionalExpression(
                                        MemberAccessExpression(SyntaxKind.SimpleMemberAccessExpression, origName, IdentifierName("HasValue")),
                                        MemberAccessExpression(SyntaxKind.SimpleMemberAccessExpression, origName, IdentifierName("Value")),
                                        DefaultExpression(ptrType.ElementType)))))));
                        arguments[param.SequenceNumber - 1] = Argument(ConditionalExpression(
                            MemberAccessExpression(SyntaxKind.SimpleMemberAccessExpression, origName, IdentifierName("HasValue")),
                            PrefixUnaryExpression(SyntaxKind.AddressOfExpression, localName),
                            LiteralExpression(SyntaxKind.NullLiteralExpression)));
                    }
                    else if (isIn && isOut && !isOptional)
                    {
                        signatureChanged = true;
                        parameters[param.SequenceNumber - 1] = parameters[param.SequenceNumber - 1]
                            .WithType(ptrType.ElementType)
                            .WithModifiers(TokenList(Token(SyntaxKind.RefKeyword)));
                        fixedBlocks.Add(VariableDeclaration(ptrType).AddVariables(
                            VariableDeclarator(localName.Identifier).WithInitializer(EqualsValueClause(
                                PrefixUnaryExpression(SyntaxKind.AddressOfExpression, origName)))));
                        arguments[param.SequenceNumber - 1] = Argument(localName);
                    }
                    else if (isOut && !isIn && !isOptional)
                    {
                        signatureChanged = true;
                        parameters[param.SequenceNumber - 1] = parameters[param.SequenceNumber - 1]
                            .WithType(ptrType.ElementType)
                            .WithModifiers(TokenList(Token(SyntaxKind.OutKeyword)));
                        fixedBlocks.Add(VariableDeclaration(ptrType).AddVariables(
                            VariableDeclarator(localName.Identifier).WithInitializer(EqualsValueClause(
                                PrefixUnaryExpression(SyntaxKind.AddressOfExpression, origName)))));
                        arguments[param.SequenceNumber - 1] = Argument(localName);
                    }
                    else if (isIn && !isOut && !isOptional)
                    {
                        // Use the "in" modifier to avoid copying the struct.
                        signatureChanged = true;
                        parameters[param.SequenceNumber - 1] = parameters[param.SequenceNumber - 1]
                            .WithType(ptrType.ElementType)
                            .WithModifiers(TokenList(Token(SyntaxKind.InKeyword)));
                        fixedBlocks.Add(VariableDeclaration(ptrType).AddVariables(
                            VariableDeclarator(localName.Identifier).WithInitializer(EqualsValueClause(
                                PrefixUnaryExpression(SyntaxKind.AddressOfExpression, origName)))));
                        arguments[param.SequenceNumber - 1] = Argument(localName);
                    }
                }
            }

            if (signatureChanged)
            {
                var leadingTrivia = Trivia(
                    DocumentationCommentTrivia(SyntaxKind.SingleLineDocumentationCommentTrivia).AddContent(
                        XmlText("/// "),
                        XmlEmptyElement("inheritdoc").AddAttributes(XmlCrefAttribute(NameMemberCref(IdentifierName(externMethodDeclaration.Identifier), ToCref(externMethodDeclaration.ParameterList)))),
                        XmlText().AddTextTokens(XmlTextNewLine(TriviaList(), "\r\n", "\r\n", TriviaList()))));
                InvocationExpressionSyntax externInvocation = InvocationExpression(QualifiedName(IdentifierName(declaringTypeName), IdentifierName(externMethodDeclaration.Identifier.Text)))
                    .AddArgumentListArguments(arguments.ToArray());
                bool hasVoidReturn = externMethodDeclaration.ReturnType is PredefinedTypeSyntax { Keyword: { RawKind: (int)SyntaxKind.VoidKeyword } };
                var body = Block()
                        .AddStatements(leadingStatements.ToArray())
                        .AddStatements(hasVoidReturn ? (StatementSyntax)ExpressionStatement(externInvocation) : ReturnStatement(externInvocation));

                foreach (var fixedExpression in fixedBlocks)
                {
                    body = Block(FixedStatement(fixedExpression, body));
                }

                MethodDeclarationSyntax friendlyDeclaration = externMethodDeclaration
                    .WithModifiers(TokenList(Token(SyntaxKind.PublicKeyword), Token(SyntaxKind.StaticKeyword), Token(SyntaxKind.UnsafeKeyword)))
                    .WithAttributeLists(List<AttributeListSyntax>())
                    .WithParameterList(ParameterList().AddParameters(parameters.ToArray()))
                    .WithLeadingTrivia(leadingTrivia)
                    .WithBody(body)
                    .WithSemicolonToken(default);
                yield return friendlyDeclaration;
            }
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
            var parameterInfo = this.ReinterpretMethodSignatureType(methodSignature.ParameterTypes[parameter.SequenceNumber - 1], parameter.GetCustomAttributes());

            // Determine the custom attributes to apply.
            var attributes = AttributeList();
            if (parameterInfo.Type is PointerTypeSyntax)
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
                parameterInfo.Type,
                SafeIdentifier(name),
                @default: null);

            if (parameterInfo.MarshalAsAttribute is object)
            {
                parameterSyntax = parameterSyntax
                    .AddAttributeLists(AttributeList().AddAttributes(parameterInfo.MarshalAsAttribute));
            }

            return parameterSyntax;
        }

        private (TypeSyntax Type, AttributeSyntax? MarshalAsAttribute) ReinterpretMethodSignatureType(TypeSyntax originalType, CustomAttributeHandleCollection customAttributes)
        {
            foreach (CustomAttributeHandle attHandle in customAttributes)
            {
                CustomAttribute att = this.mr.GetCustomAttribute(attHandle);
                if (this.IsAttribute(att, MicrosoftWindowsSdk, NativeTypeInfoAttribute))
                {
                    var args = att.DecodeValue(this.customAttributeTypeProvider);
                    if (args.FixedArguments[0].Value is object value)
                    {
                        UnmanagedType unmanagedType = (UnmanagedType)value;
                        switch (unmanagedType)
                        {
                            case UnmanagedType.Bool: return (PredefinedType(Token(SyntaxKind.BoolKeyword)), MarshalAs(unmanagedType));
                            case UnmanagedType.LPWStr:
                                if (originalType is PointerTypeSyntax { ElementType: PredefinedTypeSyntax { Keyword: { RawKind: (int)SyntaxKind.UShortKeyword } } })
                                {
                                    return (PointerType(PredefinedType(Token(SyntaxKind.CharKeyword))), null);
                                }

                                break;

                            case UnmanagedType.LPStr:
                                if (originalType is PointerTypeSyntax { ElementType: PredefinedTypeSyntax { Keyword: { RawKind: (int)SyntaxKind.SByteKeyword } } })
                                {
                                    return (PointerType(PredefinedType(Token(SyntaxKind.ByteKeyword))), null);
                                }

                                break;

                            default:
                                break;
                        }
                    }

                    break;
                }

                if (this.IsAttribute(att, MicrosoftWindowsSdk, RIAAFreeAttribute))
                {
                    var args = att.DecodeValue(this.customAttributeTypeProvider);
                    if (args.FixedArguments[0].Value is string releaseMethod && this.GenerateSafeHandle(releaseMethod) is TypeSyntax safeHandleType)
                    {
                        return (safeHandleType, null);
                    }
                }
            }

            return (originalType, null);
        }

        private (TypeSyntax FieldType, PropertyDeclarationSyntax? Property) ReinterpretFieldType(string fieldName, TypeSyntax originalType, CustomAttributeHandleCollection customAttributes)
        {
            // For fields, we don't want to use MarshalAs attributes because that turns our structs into managed types,
            // and thus cannot be used with pointers.
            foreach (CustomAttributeHandle attHandle in customAttributes)
            {
                CustomAttribute att = this.mr.GetCustomAttribute(attHandle);
                if (this.IsAttribute(att, MicrosoftWindowsSdk, NativeTypeInfoAttribute))
                {
                    var args = att.DecodeValue(this.customAttributeTypeProvider);
                    if (args.FixedArguments[0].Value is object value)
                    {
                        UnmanagedType unmanagedType = (UnmanagedType)value;
                        switch (unmanagedType)
                        {
                            case UnmanagedType.Bool:
                                // The native memory is 4 bytes long, so we can't use C# bool which is just 1 byte long.
                                // Use int for the field, and generate a property accessor.
                                ExpressionSyntax hiddenFieldAccess = MemberAccessExpression(
                                    SyntaxKind.SimpleMemberAccessExpression,
                                    ThisExpression(),
                                    IdentifierName(GetHiddenFieldName(fieldName)));
                                var property = PropertyDeclaration(PredefinedType(Token(SyntaxKind.BoolKeyword)), fieldName)
                                    .AddModifiers(Token(SyntaxKind.PublicKeyword))
                                    .AddAccessorListAccessors(
                                        AccessorDeclaration(SyntaxKind.GetAccessorDeclaration)
                                            .WithExpressionBody(ArrowExpressionClause(BinaryExpression(
                                                SyntaxKind.NotEqualsExpression,
                                                hiddenFieldAccess,
                                                LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(0)))))
                                            .WithSemicolonToken(Token(SyntaxKind.SemicolonToken)),
                                        AccessorDeclaration(SyntaxKind.SetAccessorDeclaration)
                                            .WithExpressionBody(ArrowExpressionClause(AssignmentExpression(
                                                SyntaxKind.SimpleAssignmentExpression,
                                                hiddenFieldAccess,
                                                ConditionalExpression(
                                                    IdentifierName("value"),
                                                    LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(1)),
                                                    LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(0))))))
                                            .WithSemicolonToken(Token(SyntaxKind.SemicolonToken)));
                                return (originalType, property);
                            case UnmanagedType.LPWStr:
                                if (originalType is PointerTypeSyntax { ElementType: PredefinedTypeSyntax { Keyword: { RawKind: (int)SyntaxKind.UShortKeyword } } })
                                {
                                    return (PointerType(PredefinedType(Token(SyntaxKind.CharKeyword))), null);
                                }

                                break;

                            case UnmanagedType.LPStr:
                                if (originalType is PointerTypeSyntax { ElementType: PredefinedTypeSyntax { Keyword: { RawKind: (int)SyntaxKind.SByteKeyword } } })
                                {
                                    return (PointerType(PredefinedType(Token(SyntaxKind.ByteKeyword))), null);
                                }

                                break;

                            default:
                                break;
                        }
                    }

                    break;
                }
            }

            return (originalType, null);
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

        private ExpressionSyntax ToHexExpressionSyntax(Constant constant)
        {
            var blobReader = this.mr.GetBlobReader(constant.Value);
            var blobReader2 = this.mr.GetBlobReader(constant.Value);
            return constant.TypeCode switch
            {
                ConstantTypeCode.SByte => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(ToHex(blobReader.ReadSByte()), blobReader2.ReadSByte())),
                ConstantTypeCode.Byte => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(ToHex(blobReader.ReadByte()), blobReader2.ReadByte())),
                ConstantTypeCode.Int16 => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(ToHex(blobReader.ReadInt16()), blobReader2.ReadInt16())),
                ConstantTypeCode.UInt16 => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(ToHex(blobReader.ReadUInt16()), blobReader2.ReadUInt16())),
                ConstantTypeCode.Int32 => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(ToHex(blobReader.ReadInt32()), blobReader2.ReadInt32())),
                ConstantTypeCode.UInt32 => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(ToHex(blobReader.ReadUInt32()), blobReader2.ReadUInt32())),
                ConstantTypeCode.Int64 => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(ToHex(blobReader.ReadInt64()), blobReader2.ReadInt64())),
                ConstantTypeCode.UInt64 => LiteralExpression(SyntaxKind.NumericLiteralExpression, Literal(ToHex(blobReader.ReadUInt64()), blobReader2.ReadUInt64())),
                _ => throw new NotSupportedException("ConstantTypeCode not supported: " + constant.TypeCode),
            };

            unsafe string ToHex<T>(T value)
                where T : unmanaged
            {
                int fullHexLength = sizeof(T) * 2;
                string hex = string.Format("0x{0:X" + fullHexLength + "}", value);
                return hex;
            }
        }
    }
}
