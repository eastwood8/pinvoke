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
    using System.Text;
    using Microsoft.CodeAnalysis;
    using Microsoft.CodeAnalysis.Text;

    [Generator]
    public class SourceGenerator : ISourceGenerator
    {
        private const string NativeMethodsAdditionalFileName = "NativeMethods.txt";

        public void Initialize(GeneratorInitializationContext context)
        {
        }

        public void Execute(GeneratorExecutionContext context)
        {
            var generator = new Generator();
            SourceText? nativeMethodsTxt = context.AdditionalFiles
                .FirstOrDefault(af => string.Equals(Path.GetFileName(af.Path), NativeMethodsAdditionalFileName, StringComparison.OrdinalIgnoreCase))
                ?.GetText(context.CancellationToken);
            if (nativeMethodsTxt is null)
            {
                return;
            }

            foreach (TextLine line in nativeMethodsTxt.Lines)
            {
                context.CancellationToken.ThrowIfCancellationRequested();
                string name = line.ToString();
                if (name.EndsWith(".*"))
                {
                    generator.GenerateAllExternMethods(name.Substring(0, name.Length - 2), context.CancellationToken);
                }
                else
                {
                    generator.GenerateExternMethod(name);
                }
            }

            context.AddSource("NativeMethods.cs", generator.CompilationUnit.ToFullString());
        }
    }
}
