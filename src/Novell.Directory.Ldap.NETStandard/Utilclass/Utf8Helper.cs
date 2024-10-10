/******************************************************************************
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
using System.Text;

namespace Novell.Directory.Ldap.Utilclass
{
    /// <summary>
    ///     The Utf8Helper utility class can validate, that a byte-sequence constitutes valid UTF-8.
    /// </summary>
    internal static class Utf8Helper
    {
        /// <summary>
        ///     Bit masks used to determine if the value of a UTF-8 byte sequence
        ///     is less than the minimum value.
        ///     If the value of a byte sequence is less than the minimum value then
        ///     the number should be encoded in fewer bytes and is invalid.  For example
        ///     If the first byte indicates that a sequence has three bytes in a
        ///     sequence. Then the top five bits cannot be zero.  Notice the index into
        ///     the array is one less than the number of bytes in a sequence.
        ///     A validity test for this could be:.
        /// </summary>
        private static readonly byte[][] LowerBoundMask =
        {
            new byte[] { 0, 0 }, new[] { (byte)0x1E, (byte)0x00 },
            new[] { (byte)0x0F, (byte)0x20 }, new[] { (byte)0x07, (byte)0x30 }, new[] { (byte)0x02, (byte)0x38 },
            new[] { (byte)0x01, (byte)0x3C },
        };

        /// <summary>mask to AND with a continuation byte: should equal continuationResult. </summary>
        private static readonly byte ContinuationMask = 0xC0;

        /// <summary>expected result of ANDing a continuation byte with continuationMask. </summary>
        private static readonly byte ContinuationResult = 0x80;

        /* **************UTF-8 Validation methods and members*******************
        * The following text is taken from draft-yergeau-rfc2279bis-02 and explains
        * UTF-8 encoding:
        *
        *In UTF-8, characters are encoded using sequences of 1 to 6 octets.
        * If the range of character numbers is restricted to U+0000..U+10FFFF
        * (the UTF-16 accessible range), then only sequences of one to four
        * octets will occur.  The only octet of a "sequence" of one has the
        * higher-order bit set to 0, the remaining 7 bits being used to encode
        * the character number.  In a sequence of n octets, n>1, the initial
        * octet has the n higher-order bits set to 1, followed by a bit set to
        * 0.  The remaining bit(s) of that octet contain bits from the number
        * of the character to be encoded.  The following octet(s) all have the
        * higher-order bit set to 1 and the following bit set to 0, leaving 6
        * bits in each to contain bits from the character to be encoded.
        *
        * The table below summarizes the format of these different octet types.
        * The letter x indicates bits available for encoding bits of the
        * character number.
        *
        * <pre>
        * Char. number range  |        UTF-8 octet sequence
        *    (hexadecimal)    |              (binary)
        * --------------------+---------------------------------------------
        * 0000 0000-0000 007F | 0xxxxxxx
        * 0000 0080-0000 07FF | 110xxxxx 10xxxxxx
        * 0000 0800-0000 FFFF | 1110xxxx 10xxxxxx 10xxxxxx
        * 0001 0000-001F FFFF | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
        * 0020 0000-03FF FFFF | 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
        * 0400 0000-7FFF FFFF | 1111110x 10xxxxxx ... 10xxxxxx
        * </pre>
        */

        /// <summary>
        ///     Given the first byte in a sequence, getByteCount returns the number of
        ///     additional bytes in a UTF-8 character sequence (not including the first
        ///     byte).
        /// </summary>
        /// <param name="b">
        ///     The first byte in a UTF-8 character sequence.
        /// </param>
        /// <returns>
        ///     the number of additional bytes in a UTF-8 character sequence.
        /// </returns>
        private static int GetByteCount(byte b)
        {
            if (b < 0x80)
            {
                return 0;
            }

            if ((b & 0xE0) == 0xC0)
            {
                return 1; // one additional byte (2 bytes total)
            }

            if ((b & 0xF0) == 0xE0)
            {
                return 2; // two additional bytes (3 bytes total)
            }

            if ((b & 0xF8) == 0xF0)
            {
                return 3; // three additional bytes (4 bytes total)
            }

            if ((b & 0xFC) == 0xF8)
            {
                return 4; // four additional bytes (5 bytes total)
            }

            if ((b & 0xFF) == 0xFC)
            {
                return 5; // five additional bytes (6 bytes total)
            }

            return -1;
        }

        /// <summary>
        ///     Determines if an array of bytes contains only valid UTF-8 characters.
        ///     UTF-8 is the standard encoding for Ldap strings.  If a value contains
        ///     data that is not valid UTF-8 then data is lost converting the
        ///     value to a Java String.
        ///     In addition, Java Strings currently use UCS2 (Unicode Code Standard
        ///     2-byte characters). UTF-8 can be encoded as USC2 and UCS4 (4-byte
        ///     characters).  Some valid UTF-8 characters cannot be represented as UCS2
        ///     characters. To determine if all UTF-8 sequences can be encoded into
        ///     UCS2 characters (a Java String), specify the. <code>isUCS2Only</code>
        ///     parameter as. <code>true</code>.
        /// </summary>
        /// <param name="array">
        ///     An array of bytes that are to be tested for valid UTF-8
        ///     encoding.
        /// </param>
        /// <param name="isUcs2Only">
        ///     true if the UTF-8 values must be restricted to fit
        ///     within UCS2 encoding (2 bytes).
        /// </param>
        /// <returns>
        ///     true if all values in the byte array are valid UTF-8
        ///     sequences.  If. <code>isUCS2Only</code> is.
        ///     <code>true</code>, the method returns false if a UTF-8
        ///     sequence generates any character that cannot be
        ///     represented as a UCS2 character (Java String).
        /// </returns>
        public static bool IsValidUtf8(byte[] array, bool isUcs2Only)
        {
            var index = 0;
            while (index < array.Length)
            {
                var count = GetByteCount(array[index]);
                if (count == 0)
                {
                    // anything that qualifies as count=0 is valid UTF-8
                    index++;
                    continue;
                }

                if (count == -1 || index + count >= array.Length || (isUcs2Only && count >= 3))
                {
                    /* Any count that puts us out of bounds for the index is
                    * invalid.  Valid UCS2 characters can only have 2 additional
                    * bytes. (three total) */
                    return false;
                }

                /* Tests if the first and second byte are below the minimum bound */
                if ((LowerBoundMask[count][0] & array[index]) == 0 &&
                    (LowerBoundMask[count][1] & array[index + 1]) == 0)
                {
                    return false;
                }

                /* testing continuation on the second and following bytes */
                for (var i = 1; i <= count; i++)
                {
                    if ((array[index + i] & ContinuationMask) != ContinuationResult)
                    {
                        return false;
                    }
                }

                index += count + 1;
            }

            return true;
        }
    }
}
