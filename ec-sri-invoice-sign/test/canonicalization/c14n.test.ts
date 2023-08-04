import { expect } from "chai";
import { c14nCanonicalize } from "../../src/canonicalization/c14n";

describe.only('cn14', () => {
  it('Removes comments, sorts attributes and namespaces, inherits and removes redundant namespaces and trims document leading and trailing whitespace', () => {
    const input = `
        <doc>
  <e1   />


  <e2   ></e2>
  <e3   name = 'elem3'   id='elem3'   />
  <e4   name='elem4'   id='elem4'   ></e4>
  <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
    xmlns:b="http://www.ietf.org"
    xmlns:a="http://www.w3.org"
    xmlns="http://example.org"/>
  <e6 xmlns="" xmlns:a="http://www.w3.org">
    <e7 xmlns="http://www.ietf.org">
      <e8 xmlns="" xmlns:a="http://www.w3.org">
        <e9 xmlns="" xmlns:a="http://www.ietf.org"/>
      </e8>
    </e7>
    <!-- Comment 2 -->

  </e6>

    <!-- Comment 3 -->

</doc>`;

    const expected = `\
<doc>
  <e1></e1>


  <e2></e2>
  <e3 id="elem3" name="elem3"></e3>
  <e4 id="elem4" name="elem4"></e4>
  <e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>
  <e6 xmlns:a="http://www.w3.org">
    <e7 xmlns="http://www.ietf.org">
      <e8 xmlns="">
        <e9 xmlns:a="http://www.ietf.org" attr="default"></e9>
      </e8>
    </e7>
    

  </e6>

    

</doc>`;

    const result = c14nCanonicalize(input);

    expect(result).to.equal(expected);
  });

  it('should replace whitespace between attributes with a single space (0x20)', () => {
    const input = `<e1   a='one'
    
    b  = 'two'  >`;

    const expected = `<e1 a="one" b="two"></e1>`;

    const result = c14nCanonicalize(input);
    expect(result).to.equal(expected);
  });

  it('should replace CR (0x0d), LF (0x0a), TAB (0x09) within attribute values with a single space (0x20)', () => {
    const input = `<e2 C=' letter


	A ' >`;

    const expected = `<e2 C=" letter    A "></e2>`;

    const result = c14nCanonicalize(input);
    expect(result).to.equal(expected);
  });

  it('should remove whitespace between the final double quotes in a start tag and the closing \'>\' and all whitespace in the closing tag', () => {
    const input = '<e3  d= "foo"  >bar</e3   >';
    const expected = '<e3 d="foo">bar</e3>'

    const result = c14nCanonicalize(input);
    expect(result).to.equal(expected);
  })
});


// COVER THIS: The letter á is changed from Latin-1 encoding e1 to UTF-8 c3 a1