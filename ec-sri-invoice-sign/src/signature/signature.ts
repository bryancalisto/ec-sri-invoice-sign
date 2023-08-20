import { c14nCanonicalize } from "../canonicalization/c14n";
import { extractPrivateKeyAndCertificateFromPkcs12, extractPrivateKeyData, extractX509Data, getHash, sign } from "../utils/cryptography";
import Utils from "../utils/utils";
import { buildKeyInfoTag } from "./templates/keyInfo";
import { buildSignatureTag } from "./templates/signature";
import { buildSignedInfoTag } from "./templates/signedInfo";
import { buildSignedPropertiesTag } from "./templates/signedProperties";

type signInvoiceXmlOptions = Partial<{
  pkcs12Password: string;
}>;

const insertSignatureIntoInvoiceXml = (invoiceXml: string, signatureXml: string) => {
  return invoiceXml.replace('</factura>', `${signatureXml}</factura>`);
}

export const signInvoiceXml = (invoiceXml: string, pkcs12Data: string | Buffer, options?: signInvoiceXmlOptions) => {
  const signingTime = Utils.getDate();
  const { privateKey, certificate } = extractPrivateKeyAndCertificateFromPkcs12(pkcs12Data, options?.pkcs12Password);
  const { exponent: certificateExponent, modulus: certificateModulus } = extractPrivateKeyData(privateKey);
  const { issuerName: x509IssuerName, serialNumber: x509SerialNumber, content: certificateContent, contentHash: x509Hash } = extractX509Data(certificate);

  // IDs
  const invoiceTagId = 'comprobante';
  // const invoiceTagRefId = `xmldsig-409823bd-3e51-475f-8240-40ad174a43d0-ref0`; // DEBUG
  const invoiceTagRefId = `InvoiceRef-${Utils.getRandomUuid()}`;
  const keyInfoTagId = `Certificate-${Utils.getRandomUuid()}`;
  const keyInfoRefTagId = `CertificateRef-${Utils.getRandomUuid()}`;
  const signedInfoTagId = `SignedInfo-${Utils.getRandomUuid()}`;
  const signedPropertiesRefTagId = `SignedPropertiesRef-${Utils.getRandomUuid()}`;
  // const signedPropertiesTagId = `xmldsig-409823bd-3e51-475f-8240-40ad174a43d0-signedprops`; // DEBUG
  const signedPropertiesTagId = `SignedProperties-${Utils.getRandomUuid()}`;
  // const signatureTagId = `xmldsig-409823bd-3e51-475f-8240-40ad174a43d0`; // DEBUG
  const signatureTagId = `Signature-${Utils.getRandomUuid()}`;
  const signatureObjectTagId = `SignatureObject-${Utils.getRandomUuid()}`;
  // const signatureValueTagId = `xmldsig-409823bd-3e51-475f-8240-40ad174a43d0-sigvalue`; // DEBUG
  const signatureValueTagId = `SignatureValue-${Utils.getRandomUuid()}`;

  // XML sections, hashes and signature
  const keyInfoTag = buildKeyInfoTag({
    certificateContent,
    certificateExponent,
    certificateModulus,
    keyInfoTagId
  });

  const signedPropertiesTag = buildSignedPropertiesTag({
    invoiceTagRefId,
    signedPropertiesTagId,
    signingTime,
    x509Hash,
    x509IssuerName,
    x509SerialNumber
  });

  const invoiceHash = getHash(c14nCanonicalize(invoiceXml));
  const signedPropertiesTagHash = getHash(c14nCanonicalize(signedPropertiesTag, { inheritedNamespaces: [{ prefix: 'xades', uri: 'http://uri.etsi.org/01903/v1.3.2#' }, { prefix: 'xades141', uri: 'http://uri.etsi.org/01903/v1.4.1#' }, { prefix: 'ds', uri: 'http://www.w3.org/2000/09/xmldsig#' }] }));
  const keyInfoTagHash = getHash(c14nCanonicalize(keyInfoTag, { inheritedNamespaces: [{ prefix: 'ds', uri: 'http://www.w3.org/2000/09/xmldsig#' }] }));

  const signedInfoTag = buildSignedInfoTag({
    invoiceHash,
    invoiceTagId,
    invoiceTagRefId,
    keyInfoRefTagId,
    keyInfoTagHash,
    keyInfoTagId,
    signedInfoTagId,
    signedPropertiesRefTagId,
    signedPropertiesTagHash,
    signedPropertiesTagId
  });

  const signedSignedInfoTag = sign(c14nCanonicalize(signedInfoTag, { inheritedNamespaces: [{ prefix: 'ds', uri: 'http://www.w3.org/2000/09/xmldsig#' }] }), privateKey);

  const signatureTag = buildSignatureTag({
    keyInfoTag,
    signatureTagId,
    signatureObjectTagId,
    signedInfoTag,
    signedSignedInfoTag,
    signatureValueTagId,
    signedPropertiesTag
  });

  return insertSignatureIntoInvoiceXml(invoiceXml, signatureTag);
}