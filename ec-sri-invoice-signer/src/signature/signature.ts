import { c14nCanonicalize } from "../canonicalization/c14n";
import { XmlProperties } from "../utils/constants";
import { extractPrivateKeyAndCertificateFromPkcs12, extractPrivateKeyData, extractX509Data, getHash, sign } from "../utils/cryptography";
import * as Utils from "../utils/utils";
import { buildKeyInfoTag } from "./templates/keyInfo";
import { buildSignatureTag } from "./templates/signature";
import { buildSignedInfoTag } from "./templates/signedInfo";
import { buildSignedPropertiesTag } from "./templates/signedProperties";

export type signInvoiceXmlOptions = Partial<{
  pkcs12Password: string;
}>;

const insertSignatureIntoInvoiceXml = (invoiceXml: string, signatureXml: string) => {
  // Extrae la etiqueta raíz con ReGexr
  const rootTagMatch = invoiceXml.match(/<(\w+)[^>]*>/);

  if (!rootTagMatch) {
    throw new Error('No se pudo determinar la etiqueta raíz del XML. Esperado "factura", "notaDebito", "comprobanteRetencion", etc');
  }

  // Obtiene el nombre del tag raíz
  const rootTag = rootTagMatch[1];

  return invoiceXml.replace(`</${rootTag}>`, `${signatureXml}</${rootTag}>`);
};

/**
 * 
 * @param invoiceXml The invoice XML to be signed.
 * @param pkcs12Data The pkcs12 file (.p12/.pfx) data expressed as a node Buffer or base64 string.
 * @param options Options are:
 * - **pkcs12Password**: The pkcs12 file password. Defaults to no password.
 * @returns 
 */
export const signInvoiceXml = (invoiceXml: string, pkcs12Data: string | Buffer, options?: signInvoiceXmlOptions) => {
  const signingTime = Utils.getDate();
  const { privateKey, certificate } = extractPrivateKeyAndCertificateFromPkcs12(pkcs12Data, options?.pkcs12Password);
  const { exponent: certificateExponent, modulus: certificateModulus } = extractPrivateKeyData(privateKey);
  const { issuerName: x509IssuerName, serialNumber: x509SerialNumber, content: certificateContent, contentHash: x509Hash } = extractX509Data(certificate);

  // IDs
  const invoiceTagId = 'comprobante';
  const invoiceTagRefId = `InvoiceRef-${Utils.getRandomUuid()}`;
  const keyInfoTagId = `Certificate-${Utils.getRandomUuid()}`;
  const keyInfoRefTagId = `CertificateRef-${Utils.getRandomUuid()}`;
  const signedInfoTagId = `SignedInfo-${Utils.getRandomUuid()}`;
  const signedPropertiesRefTagId = `SignedPropertiesRef-${Utils.getRandomUuid()}`;
  const signedPropertiesTagId = `SignedProperties-${Utils.getRandomUuid()}`;
  const signatureTagId = `Signature-${Utils.getRandomUuid()}`;
  const signatureObjectTagId = `SignatureObject-${Utils.getRandomUuid()}`;
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
  const signedPropertiesTagHash = getHash(c14nCanonicalize(signedPropertiesTag, { inheritedNamespaces: [{ prefix: 'xades', uri: XmlProperties.namespaces.xades }, { prefix: 'ds', uri: XmlProperties.namespaces.ds }] }));
  const keyInfoTagHash = getHash(c14nCanonicalize(keyInfoTag, { inheritedNamespaces: [{ prefix: 'ds', uri: XmlProperties.namespaces.ds }] }));

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

  const signedSignedInfoTag = sign(c14nCanonicalize(signedInfoTag, { inheritedNamespaces: [{ prefix: 'ds', uri: XmlProperties.namespaces.ds }] }), privateKey);

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