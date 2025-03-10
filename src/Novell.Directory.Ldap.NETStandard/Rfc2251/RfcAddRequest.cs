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

namespace Novell.Directory.Ldap.Rfc2251
{
    /// <summary>
    ///     Represents the Ldap Add Request.
    ///     <pre>
    ///         AddRequest ::= [APPLICATION 8] SEQUENCE {
    ///         entry           LdapDN,
    ///         attributes      AttributeList }
    ///     </pre>
    /// </summary>
    public class RfcAddRequest : Asn1Sequence, IRfcRequest
    {
        // *************************************************************************
        // Constructors for AddRequest
        // *************************************************************************

        /// <summary>
        ///     Constructs an RFCAddRequest.
        /// </summary>
        /// <param name="entry">
        ///     the entry.
        /// </param>
        /// <param name="attributes">
        ///     the Attributes making up the Entry.
        /// </param>
        public RfcAddRequest(RfcLdapDn entry, RfcAttributeList attributes)
            : base(2)
        {
            Add(entry);
            Add(attributes);
        }

        /// <summary>
        ///     Constructs a new Add Request using data from an existing request.
        /// </summary>
        /// <param name="origRequest">
        ///     the original request data.
        /// </param>
        /// <param name="baseDn">
        ///     if not null, replaces the dn of the original request.
        /// </param>
        internal RfcAddRequest(Asn1Object[] origRequest, string baseDn)
            : base(origRequest, origRequest.Length)
        {
            // Replace the base if specified, otherwise keep original base
            if (baseDn != null)
            {
                this[0] = new RfcLdapDn(baseDn);
            }
        }

        /// <summary> Gets the attributes of the entry.</summary>
        public RfcAttributeList Attributes => (RfcAttributeList)this[1];

        public IRfcRequest DupRequest(string baseDn, string filter, bool request)
        {
            return new RfcAddRequest(ToArray(), baseDn);
        }

        public string GetRequestDn()
        {
            return ((RfcLdapDn)this[0]).StringValue();
        }

        // *************************************************************************
        // Accessors
        // *************************************************************************

        /// <summary>
        ///     Override getIdentifier to return an application-wide id.
        ///     <pre>
        ///         ID = CLASS: APPLICATION, FORM: CONSTRUCTED, TAG: 8. (0x68)
        ///     </pre>
        /// </summary>
        public override Asn1Identifier GetIdentifier()
        {
            return new Asn1Identifier(Asn1Identifier.Application, true, LdapMessage.AddRequest);
        }
    }
}
