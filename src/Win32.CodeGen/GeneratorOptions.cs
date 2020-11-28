// Copyright © .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Win32.CodeGen
{
    using System;

    public record GeneratorOptions
    {
        public bool WideCharOnly { get; init; } = true;

        public string? OneClass { get; init; } = "PInvoke";

        public string Namespace { get; init; } = "Microsoft.Windows.Sdk";

        public bool Public { get; init; }

        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(this.Namespace))
            {
                throw new InvalidOperationException("The namespace must be set.");
            }
        }
    }
}
