﻿// Copyright (c) to owners found in https://github.com/AArnott/pinvoke/blob/master/COPYRIGHT.md. All rights reserved.
// Licensed under the MIT license. See LICENSE.txt file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using PInvoke;
using Xunit;
using static PInvoke.Magnification;

public class MagnificationFacts
{
    [Fact]
    public void InitializeThenDeinitialize()
    {
        Assert.True(MagInitialize());
        Assert.True(MagUninitialize());
    }

    [Fact]
    public void MAGCOLOREFFECT_IsRightSize()
    {
        Assert.Equal(sizeof(float) * 5 * 5, Marshal.SizeOf<MAGCOLOREFFECT>());
    }

    [Fact]
    public void MAGCOLOREFFECT_MultidimensionalArray()
    {
        var effect = default(MAGCOLOREFFECT);
        Assert.Throws<ArgumentOutOfRangeException>(() => effect[5, 0]);
        Assert.Throws<ArgumentOutOfRangeException>(() => effect[0, 5]);
        Assert.Throws<ArgumentOutOfRangeException>(() => effect[5, 0] = 0);
        Assert.Throws<ArgumentOutOfRangeException>(() => effect[0, 5] = 0);

        effect[0, 0] = 10.0f;
        effect[0, 1] = 10.1f;
        effect[1, 2] = 11.2f;
        effect[4, 4] = 14.4f;

        Assert.Equal(10.0f, effect[0, 0]);
        Assert.Equal(10.1f, effect[0, 1]);
        Assert.Equal(11.2f, effect[1, 2]);
        Assert.Equal(14.4f, effect[4, 4]);
    }

    [Fact]
    public void MAGTRANSFORM_IsRightSize()
    {
        Assert.Equal(sizeof(float) * 3 * 3, Marshal.SizeOf<MAGTRANSFORM>());
    }

    [Fact]
    public void MAGTRANSFORM_MultidimensionalArray()
    {
        var effect = default(MAGTRANSFORM);
        Assert.Throws<ArgumentOutOfRangeException>(() => effect[3, 0]);
        Assert.Throws<ArgumentOutOfRangeException>(() => effect[0, 3]);
        Assert.Throws<ArgumentOutOfRangeException>(() => effect[3, 0] = 0);
        Assert.Throws<ArgumentOutOfRangeException>(() => effect[0, 3] = 0);

        effect[0, 0] = 10.0f;
        effect[0, 1] = 10.1f;
        effect[1, 2] = 11.2f;
        effect[2, 2] = 12.2f;

        Assert.Equal(10.0f, effect[0, 0]);
        Assert.Equal(10.1f, effect[0, 1]);
        Assert.Equal(11.2f, effect[1, 2]);
        Assert.Equal(12.2f, effect[2, 2]);
    }
}
