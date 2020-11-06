// Copyright © .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Win32MetaGeneration
{
    using System;
    using System.Collections.Immutable;
    using System.Reflection.Metadata;
    using Microsoft.CodeAnalysis;
    using Microsoft.CodeAnalysis.CSharp;
    using Microsoft.CodeAnalysis.CSharp.Syntax;
    using Microsoft.CodeAnalysis.Editing;
    using static Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

    internal class SignatureTypeProvider : ISignatureTypeProvider<TypeSyntax, IGenericContext>
    {
        private static readonly TypeSyntax IntPtrTypeSyntax = IdentifierName(nameof(IntPtr));
        private static readonly TypeSyntax UIntPtrTypeSyntax = IdentifierName(nameof(UIntPtr));
        private readonly CSharpCompilation compilation;
        private readonly SyntaxGenerator syntaxGenerator;
        private readonly Generator owner;

        internal SignatureTypeProvider(CSharpCompilation compilation, SyntaxGenerator syntaxGenerator, Generator owner)
        {
            this.compilation = compilation;
            this.syntaxGenerator = syntaxGenerator;
            this.owner = owner;
        }

        public TypeSyntax GetPointerType(TypeSyntax elementType) => PointerType(elementType);

        public TypeSyntax GetPrimitiveType(PrimitiveTypeCode typeCode)
        {
            return typeCode switch
            {
                PrimitiveTypeCode.Char => PredefinedType(Token(SyntaxKind.CharKeyword)),
                PrimitiveTypeCode.Boolean => PredefinedType(Token(SyntaxKind.BoolKeyword)),
                PrimitiveTypeCode.SByte => PredefinedType(Token(SyntaxKind.SByteKeyword)),
                PrimitiveTypeCode.Byte => PredefinedType(Token(SyntaxKind.ByteKeyword)),
                PrimitiveTypeCode.Int16 => PredefinedType(Token(SyntaxKind.ShortKeyword)),
                PrimitiveTypeCode.UInt16 => PredefinedType(Token(SyntaxKind.UShortKeyword)),
                PrimitiveTypeCode.Int32 => PredefinedType(Token(SyntaxKind.IntKeyword)),
                PrimitiveTypeCode.UInt32 => PredefinedType(Token(SyntaxKind.UIntKeyword)),
                PrimitiveTypeCode.Int64 => PredefinedType(Token(SyntaxKind.LongKeyword)),
                PrimitiveTypeCode.UInt64 => PredefinedType(Token(SyntaxKind.ULongKeyword)),
                PrimitiveTypeCode.Single => PredefinedType(Token(SyntaxKind.FloatKeyword)),
                PrimitiveTypeCode.Double => PredefinedType(Token(SyntaxKind.DoubleKeyword)),
                PrimitiveTypeCode.Object => PredefinedType(Token(SyntaxKind.ObjectKeyword)),
                PrimitiveTypeCode.String => PredefinedType(Token(SyntaxKind.StringKeyword)),
                PrimitiveTypeCode.IntPtr => IntPtrTypeSyntax,
                PrimitiveTypeCode.UIntPtr => UIntPtrTypeSyntax,
                PrimitiveTypeCode.Void => PredefinedType(Token(SyntaxKind.VoidKeyword)),
                _ => throw new NotSupportedException("Unsupported type code: " + typeCode),
            };
        }

        public TypeSyntax GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind)
        {
            var td = reader.GetTypeDefinition(handle);
            string name = reader.GetString(td.Name);

            // Take this opportunity to ensure the type exists too.
            this.owner.GenerateInteropType(handle);

            return IdentifierName(name);
        }

        public TypeSyntax GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind)
        {
            var tr = reader.GetTypeReference(handle);
            string name = reader.GetString(tr.Name);
            return IdentifierName(name);
        }

        public TypeSyntax GetArrayType(TypeSyntax elementType, ArrayShape shape) => throw new NotImplementedException();

        public TypeSyntax GetByReferenceType(TypeSyntax elementType) => throw new NotImplementedException();

        public TypeSyntax GetFunctionPointerType(MethodSignature<TypeSyntax> signature) => throw new NotImplementedException();

        public TypeSyntax GetGenericInstantiation(TypeSyntax genericType, ImmutableArray<TypeSyntax> typeArguments) => throw new NotImplementedException();

        public TypeSyntax GetGenericMethodParameter(IGenericContext genericContext, int index) => throw new NotImplementedException();

        public TypeSyntax GetGenericTypeParameter(IGenericContext genericContext, int index) => throw new NotImplementedException();

        public TypeSyntax GetModifiedType(TypeSyntax modifier, TypeSyntax unmodifiedType, bool isRequired) => throw new NotImplementedException();

        public TypeSyntax GetPinnedType(TypeSyntax elementType) => throw new NotImplementedException();

        public TypeSyntax GetSZArrayType(TypeSyntax elementType) => throw new NotImplementedException();

        public TypeSyntax GetTypeFromSpecification(MetadataReader reader, IGenericContext genericContext, TypeSpecificationHandle handle, byte rawTypeKind) => throw new NotImplementedException();
    }

#pragma warning disable SA1201 // Elements should appear in the correct order
    internal interface IGenericContext
#pragma warning restore SA1201 // Elements should appear in the correct order
    {
    }
}
