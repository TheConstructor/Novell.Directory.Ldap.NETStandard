﻿/******************************************************************************
* The MIT License
* Copyright (c) 2003 Novell Inc.  www.novell.com
*
* Permission is hereby granted, free of charge, to any person obtaining  a copy
* of this software and associated documentation files (the Software), to deal
* in the Software without restriction, including  without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to  permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*******************************************************************************/

using System;

namespace Novell.Directory.Ldap.Utilclass
{
    /// <summary>
    ///     Encapsulates a qualifier in a Schema definition.  Definitions that are not
    ///     in rfc2252.  Begins with 'X-'.
    /// </summary>
    public class AttributeQualifier
    {
        private readonly string[] _values;

        public AttributeQualifier(string name, string[] value)
        {
            if (name == null || value == null)
            {
                throw new ArgumentException("A null name or value " +
                                            "was passed in for a schema definition qualifier");
            }

            Name = name;
            _values = (string[])value.Clone();
        }

        public string Name { get; }

        public string[] Values => _values.IsEmpty() ? null : (string[])_values.Clone();
    }
}
