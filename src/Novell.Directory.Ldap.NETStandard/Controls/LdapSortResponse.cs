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

using Novell.Directory.Ldap.Asn1;
using System.IO;

namespace Novell.Directory.Ldap.Controls
{
    /// <summary>
    ///     LdapSortResponse - will be added in newer version of Ldap
    ///     Controls draft.
    /// </summary>
    public class LdapSortResponse : LdapControl
    {
        /// <summary>
        ///     This constructor is usually called by the SDK to instantiate an
        ///     a LdapControl corresponding to the Server response to a Ldap
        ///     Sort Control request.  Application programmers should not have
        ///     any reason to call the constructor.  This constructor besides
        ///     constructing a LdapControl object parses the contents of the response
        ///     control.
        ///     RFC 2891 defines this response control as follows:
        ///     The controlValue is an OCTET STRING, whose
        ///     value is the BER encoding of a value of the following SEQUENCE:
        ///     SortResult ::= SEQUENCE {
        ///     sortResult  ENUMERATED {
        ///     success                   (0), -- results are sorted
        ///     operationsError           (1), -- server internal failure
        ///     timeLimitExceeded         (3), -- timelimit reached before
        ///     -- sorting was completed
        ///     strongAuthRequired        (8), -- refused to return sorted
        ///     -- results via insecure
        ///     -- protocol
        ///     adminLimitExceeded       (11), -- too many matching entries
        ///     -- for the server to sort
        ///     noSuchAttribute          (16), -- unrecognized attribute
        ///     -- type in sort key
        ///     inappropriateMatching    (18), -- unrecognized or
        ///     -- inappropriate matching
        ///     -- rule in sort key
        ///     insufficientAccessRights (50), -- refused to return sorted
        ///     -- results to this client
        ///     busy                     (51), -- too busy to process
        ///     unwillingToPerform       (53), -- unable to sort
        ///     other                    (80)
        ///     },
        ///     attributeType [0] AttributeDescription OPTIONAL }.
        /// </summary>
        /// <param name="oid">
        ///     The OID of the control, as a dotted string.
        /// </param>
        /// <param name="critical">
        ///     True if the Ldap operation should be discarded if
        ///     the control is not supported. False if
        ///     the operation can be processed without the control.
        /// </param>
        /// <param name="values">
        ///     The control-specific data.
        /// </param>
        public LdapSortResponse(string oid, bool critical, byte[] values)
            : base(oid, critical, values)
        {
            // Create a decoder object
            var decoder = new LberDecoder();
            if (decoder == null)
            {
                throw new IOException("Decoding error");
            }

            // We should get back an enumerated type
            var asnObj = decoder.Decode(values);

            if (asnObj is not Asn1Sequence sequence)
            {
                throw new IOException("Decoding error");
            }

            var asn1Enum = sequence[0];
            if (asn1Enum is Asn1Enumerated enumerated)
            {
                ResultCode = enumerated.IntValue();
            }

            // Second element is the attributeType
            if (sequence.Count > 1)
            {
                var asn1String = sequence[1];
                if (asn1String is Asn1OctetString octetString)
                {
                    FailedAttribute = octetString.StringValue();
                }
            }
        }

        /// <summary>
        ///     If not null, this returns the attribute that caused the sort
        ///     operation to fail.
        /// </summary>
        public virtual string FailedAttribute { get; }

        /// <summary> Returns the result code from the sort.</summary>
        public virtual int ResultCode { get; }
    }
}
