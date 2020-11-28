// Copyright © .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Win32.CodeGen
{
    using System;

    public record GeneratorOptions
    {
        public bool WideCharOnly { get; init; } = true;

        public bool GroupByModule { get; init; } = true;

        public string Namespace { get; init; } = "Microsoft.Windows.Sdk";

        public string SingleClassName { get; init; } = "PInvoke";

        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(this.Namespace))
            {
                throw new InvalidOperationException("The namespace must be set.");
            }
        }
    }
}
