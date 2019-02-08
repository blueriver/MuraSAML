// Coldfusion Component for authenticating users via ADFS Saml 2.0
// Author: Jim Hammons
// @output       false
// @accessors    true
component{
    // @type struct
    // @hint Contains the attributes returned in a valid response
    function init(){
        return this;
    }

    // @hint         Reads Metadata File and returns
    // @return       String
    public function getIDPpost(){
        var rtn = "";
        try{

            var fedFile = fileRead( GetDirectoryFromPath(GetCurrentTemplatePath()) & "federationmetadata.xml" );
            var fedXML = XMLParse(fedFile);
            var fedNode = xmlSearch(fedXML, "//*[local-name()='IDPSSODescriptor']/*[local-name()='SingleSignOnService' and @Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']");
            rtn = fedNode[1].XmlAttributes.Location;

        }catch (Any e) {/* Put any logic here if you want to capture*/}

        return rtn;
    }

    // @hint         Validates Certificate in FederatedMetadata.xml and updates if expired or forced
    // @force        Boolean
    // @return       Boolean
    remote function checkFedMeta(boolean force = false, string env = "prod") {

        try{
            var expire = CreateDateTime("1972", "9", "30", "1", "1", "1"); // Create Expired date as default

            if (not arguments.force and fileExists(expandPath( "federationmetadata.xml" ))) {
                var fedFile = fileRead( expandPath( "federationmetadata.xml" ) );
                var fedXML = XMLParse(fedFile);
                var doc = fedXML.getDocumentElement();
                var rtn = false;

                // Check Signature
                var SecInit = CreateObject("Java", "org.apache.xml.security.Init").Init().init();
                var SignatureConstants=CreateObject("Java", "org.apache.xml.security.utils.Constants");
                var SignatureSpecNS = SignatureConstants.SignatureSpecNS;
                var xmlSignatureClass = CreateObject("Java", "org.apache.xml.security.signature.XMLSignature");
                var xmlSignature = xmlSignatureClass.init(doc.getElementsByTagNameNS(SignatureSpecNS,"Signature").item(0),javacast("string",""));
                var keyInfo = xmlSignature.getKeyInfo();

                var X509CertificateResolverCN = "org.apache.xml.security.keys.keyresolver.implementations.X509CertificateResolver";
                var keyResolver=CreateObject("Java", X509CertificateResolverCN).init();
                keyInfo.registerInternalKeyResolver(keyResolver);
                var x509cert = keyInfo.getX509Certificate();
                expire = x509cert.getNotAfter();
            }
            newfile = false;
            if (DateCompare(Now(), expire,"s") >= 0) {
                // Signature is Expired. Grab new FederationMetadata.xml
                // NOTE: You may need to add the cert for the address below into the Coldfusion/JVM Keystore...
                // Pass in Environment as arguments.env for dev/uat. Defaults to production IDP.
                var setUrl = "YOUR IDP's FEDERATED METADATA FILE";
                cfhttp(url=setUrl, method="get", path=GetDirectoryFromPath(GetCurrentTemplatePath()), file="federationmetadata.xml") {};
                //
                rtn = true;
            }

        }catch (Any e) { rtn = false; }

        return rtn;
    }

    // @hint         Handles creating a valid AuthN payload
    // @issuer       String (Required)
    // @consumer     String (Required)
    // @asString     Boolean
    // @return       String
    public function buildAuthn(required string issuer, required string consumer, boolean asString = false){
        try{

            var reqTS = DateFormat(Now(), "yyyy-mm-dd") & 'T' & TimeFormat(Now(), "HH:nn:ss") & '.343Z';
            var reqID = "acf-" & createUUID();
            var authnXML = "";

            savecontent variable="authnXML" {
                WriteOutput('<?xml version="1.0" encoding="UTF-8"?>');
                WriteOutput('<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ');
                    WriteOutput('AssertionConsumerServiceURL="https://' & arguments.consumer & '" ');
                    WriteOutput('Destination="' & this.getIDPpost() & '" ');
                    WriteOutput('ID="' & reqID & '" ');
                    WriteOutput('IssueInstant="' & reqTS & '" ');
                    WriteOutput('ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0">');
                WriteOutput('<samlp:Issuer xmlns:samlp="urn:oasis:names:tc:SAML:2.0:assertion">https://' & arguments.issuer & '</samlp:Issuer>');
                WriteOutput('<saml2p:NameIDPolicy xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/>');
                WriteOutput('</samlp:AuthnRequest>');
            }

            if (!arguments.asString) {
                authnXML = ToBase64(authnXML);
            }

        }catch (Any e) { authnXML = "ERROR: Unable to create AuthN."; }

        return authnXML;
    }

    // @hint         Handles creating a SpMetaDataFile.xml for first time IDP configuration
    // @consumer     String (Required)
    // @return       none
    public function buildSPMeta(required string issuer, required array consumer, string fileLocation=""){
        try{

            var reqTS = DateFormat(Now(), "yyyy-mm-dd") & 'T' & TimeFormat(Now(), "HH:nn:ss") & '.343Z';
            var reqID = "acf-" & createUUID();
            var spMetaXML = "";
            if (Len(Trim(arguments.fileLocation)) and DirectoryExists(ExpandPath(arguments.fileLocation))) {
                var spMetaFile = ExpandPath(arguments.fileLocation & "/SpMetaDataFile.xml");
            } else {
                var spMetaFile = GetDirectoryFromPath(GetCurrentTemplatePath()) & "SpMetaDataFile.xml";
            }
            savecontent variable="spMetaXML" {
                WriteOutput('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>');
                WriteOutput('<ns7:EntityDescriptor xmlns="http://www.w3.org/2005/08/addressing" xmlns:ns2="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:ns3="http://docs.oasis-open.org/wsfed/authorization/200706" xmlns:ns4="http://www.w3.org/2001/04/xmlenc##" xmlns:ns5="http://www.w3.org/2000/09/xmldsig##" xmlns:ns6="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:ns7="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ns8="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ns9="http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702" ');
                    WriteOutput('entityID="https://' & arguments.issuer & '">');
                WriteOutput('<ns7:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">');
                for (acs=1;acs LTE ArrayLen(arguments.consumer);acs=acs+1) {
                    WriteOutput('<ns7:AssertionConsumerService index="' & Val(acs-1) & '" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://' & arguments.consumer[acs] & '"/>');
                }
                WriteOutput('</ns7:SPSSODescriptor></ns7:EntityDescriptor>');
            }

            FileWrite(spMetaFile, spMetaXML);

        }catch (Any e) {  }

    }

    // @hint         Handles validating the saml response from the IDP
    // @response     String (Required)
    // @verbose      Boolean
    // @return       Struct
    public struct function processResponse(required string response, boolean verbose = false){
        var sigValid = false;
        var respXML = "";
        var passError = "";
        // Build Return Struct
        var rtnStruct = StructNew();
            rtnStruct.request = StructNew();
            rtnStruct.request.failReason = "";
            rtnStruct.request.processStack = ArrayNew(1);
        try{
            respXML ="";
            try {
                respXML = XmlParse(ToString(ToBinary(arguments.response)));
                if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Response Converted from Base64"); }
            }catch (Any e) { }

            if(not isXML(respXML)) {
                try {
                    respXML = XmlParse(ToString(ToBinary(arguments.response)));
                    if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Response Converted from Url Encoded Base64"); }
                }catch (Any e) { }
            }

            if(not isXML(respXML)) {
                try {
                    var b64decoder = CreateObject("Java", "org.apache.commons.codec.binary.Base64");
                    var decoded = b64decoder.decode(arguments.response);
                    var respXML = XmlParse(createObject("java","java.lang.String").init(decoded));
                    if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Response Converted from Java Base64 Decoder"); }
                }catch (Any e) { if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Response Not Bae64"); } }
            }

            var doc = respXML.getDocumentElement();
            // Resolve ID issues with DOM3
            var idResolver = CreateObject("Java", "org.apache.xml.security.utils.IdResolver");
            var assertionElement = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion").item(0);
            var attrStore = assertionElement.getAttributes();
            var idAttr = CreateObject("Java","org.w3c.dom.Attr");
            var idAttr = attrStore.getNamedItem("ID");
            idResolver.registerElementById(assertionElement, idAttr);
            if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"DOM Processed"); }

            // Validate Signature
            var SecInit = CreateObject("Java", "org.apache.xml.security.Init").Init().init();
            var SignatureConstants=CreateObject("Java", "org.apache.xml.security.utils.Constants");
            var SignatureSpecNS = SignatureConstants.SignatureSpecNS;
            var xmlSignatureClass = CreateObject("Java", "org.apache.xml.security.signature.XMLSignature");
            var xmlSignature = xmlSignatureClass.init(doc.getElementsByTagNameNS(SignatureSpecNS,"Signature").item(0),javacast("string",""));
            var keyInfo = xmlSignature.getKeyInfo();

            var X509CertificateResolverCN = "org.apache.xml.security.keys.keyresolver.implementations.X509CertificateResolver";
            var keyResolver=CreateObject("Java", X509CertificateResolverCN).init();
            keyInfo.registerInternalKeyResolver(keyResolver);
            var x509cert = keyInfo.getX509Certificate();
            if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Signature Object Staged"); }

            // Is the Sig Valid?
            var sigValid = xmlSignature.checkSignatureValue(x509cert);
            if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Signature Checked"); }

            //Extract conditions
            var conditionElement = doc.getElementsByTagName("Conditions").item(0);
            var conditions = conditionElement.getAttributes();
            var condBefore = conditions.getNamedItem("NotBefore").getNodeValue();
            var condAfter = conditions.getNamedItem("NotOnOrAfter").getNodeValue();
            if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Conditions Staged"); }

            var requestTS = DateAdd("s", 2, Now());

            if (YesNoFormat(sigValid)) {
                rtnStruct.authvalid = true;
                if (DateCompare(requestTS, DateConvertISO8601(condBefore),"s") < 0) {
                    rtnStruct.authvalid = false;
                    rtnStruct.request.failReason = "Not Before";
                    if (arguments.verbose) {
                        rtnStruct.request.error = "Authentication must not be before " & DateConvertISO8601(condBefore) & ". Request made on " & requestTS & ".";
                    }
                } else if (false && DateCompare(requestTS, DateConvertISO8601(condAfter),"s") >= 0) {
                    rtnStruct.authvalid = false;
                    rtnStruct.request.failreason = "Not On or After";
                    if (arguments.verbose) {
                        rtnStruct.request.error = "Authentication must not be on or after " & DateConvertISO8601(condAfter) & ". Request made on " & requestTS & ".";
                    }
                }
                if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Conditions Tested"); }
            } else {
                rtnStruct.authvalid = false;
                rtnStruct.request.valid = false;
                rtnStruct.request.failReason = "Invalid Signature";
            }
            if (arguments.verbose) {
                rtnStruct.request.certExpire = x509cert.getNotAfter();
                rtnStruct.request.testNotbefore = DateConvertISO8601(condBefore) & " (" & DateCompare(requestTS, DateConvertISO8601(condBefore),"s") & ")";
                rtnStruct.request.testOnorafter = DateConvertISO8601(condAfter) & " (" & DateCompare(requestTS, DateConvertISO8601(condAfter),"s") & ")";
                rtnStruct.request.testAuth = requestTS;
                rtnStruct.request.testSig = sigValid;
            }

            // Extract User
            var userStruct = StructNew();

            if (YesNoFormat(sigValid) or arguments.verbose) {
                var userNode = xmlSearch(respXML, "//*[local-name()='AttributeStatement']");
                for (usr=1;usr LTE ArrayLen(userNode[1].XmlChildren);usr=usr+1) {
                    name = userNode[1].XmlChildren[usr].XmlAttributes.Name;
                    var valArray = ArrayNew(1);
                    var usrval=1;
                    for (usrval=1;usrval LTE ArrayLen(userNode[1].XmlChildren[usr].XmlChildren);usrval=usrval+1) {
                        valArray[usrval] = userNode[1].XmlChildren[usr].XmlChildren[usrval].XmlText;
                    }
                    userStruct[name] = valArray;
                    // Places AccountName into the better named racf entry in the array. May need to adjust based on your applications attributes.
                    // Alternatively you can grab from NameID in the Saml Reponse, but it is not in the AttributeStatement so this loop will not see it.
                    if (name contains "samaccountname") {
                        userStruct["racf"] = valArray;
                    }
                }
                rtnStruct.user = userStruct;
                if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"User Information Extracted"); }
            }

        }catch (Any e) {
            rtnStruct.authvalid = false;
            rtnStruct.request.failReason = "Core Failure";
						writeLog(type="Error", file="exception", text="Error Decoding SAML Response: #serializeJSON(e.stacktrace)#");
            if (arguments.verbose and structKeyExists(e, "message")) {
                rtnStruct.request.error = e.message;
            }
        }

        return rtnStruct;
    }

    // @hint                 Convert a date in ISO 8601 format to an ODBC datetime.
    // @ISO8601dateString    string  The ISO8601 date string. (Required)
    // @inZoneOffset         numeric The timezone offset.
    // @return               Datetime
    // @author               David Satz (david_satz@hyperion.com)
    private function DateConvertISO8601(required string ISO8601dateString, numeric inZoneOffset = 0) {
        var targetZoneOffset = arguments.inZoneOffset;
        if (targetZoneOffset eq 0) {
            // Eastern Standard Time Offset
            targetZoneOffset = -5;
            // Get Server Timezon Info
            var TimeZoneInfo        = GetTimeZoneInfo();
            // If Daylight Savings Time
            if ( TimeZoneInfo.isDSTOn ) {
                targetZoneOffset = targetZoneOffset  + 1;
            }
        }
        var rawDatetime = left(ISO8601dateString,10) & " " & mid(ISO8601dateString,12,8);
        // adjust offset based on offset given in date string
        if (uCase(mid(ISO8601dateString,20,1)) neq "Z")
            targetZoneOffset = targetZoneOffset -  val(mid(ISO8601dateString,20,3)) ;
        return DateAdd("h", targetZoneOffset, CreateODBCDateTime(rawDatetime));
    }

}
