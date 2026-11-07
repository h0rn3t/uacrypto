package pki

import "testing"

// The documents and outputs are the examples of the W3C recommendations:
// Exclusive XML Canonicalization 1.0, section 2.2, and Canonical XML 1.0,
// examples 3.3 and 3.4 without their DTD (so without the default attribute
// of e9 and with normNames and normId left out), whose output under
// exclusive canonicalization differs from the inclusive one only in the
// namespace declarations of e6 and e9.
func TestCanonical(t *testing.T) {
	tests := []struct {
		name, doc, id, want string
	}{
		{
			name: "exc-c14n 2.2, subtree",
			doc: "<n0:local xmlns:n0=\"foo:bar\" xmlns:n3=\"ftp://example.org\">\n  <n1:elem2 Id=\"e\" xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n" +
				"    <n3:stuff xmlns:n3=\"ftp://example.org\"/>\n  </n1:elem2>\n</n0:local>",
			id: "e",
			want: "<n1:elem2 xmlns:n1=\"http://example.net\" Id=\"e\" xml:lang=\"en\">\n" +
				"    <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n  </n1:elem2>",
		},
		{
			name: "c14n 3.3, start and end tags",
			doc: "<?xml version=\"1.0\"?>\n<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = \"elem3\"   id=\"elem3\"   />\n" +
				"   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n" +
				"   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n      xmlns:b=\"http://www.ietf.org\"\n" +
				"      xmlns:a=\"http://www.w3.org\"\n      xmlns=\"http://example.org\"/>\n" +
				"   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n" +
				"         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/>\n" +
				"         </e8>\n      </e7>\n   </e6>\n</doc>\n<!-- after -->",
			want: "<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n   <e4 id=\"elem4\" name=\"elem4\"></e4>\n" +
				"   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n" +
				"   <e6>\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9></e9>\n" +
				"         </e8>\n      </e7>\n   </e6>\n</doc>",
		},
		{
			name: "c14n 3.4, character modifications",
			doc: "<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n" +
				"   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n" +
				"   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n" +
				"   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n</doc>",
			want: "<doc>\n   <text>First line&#xD;\nSecond line</text>\n   <value>2</value>\n" +
				"   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n" +
				"   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n" +
				"   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n</doc>",
		},
		{
			// XML 1.0, 3.3.3: white space written in an attribute value is a
			// space, a line end one space; a character reference stays.
			name: "attribute value normalization",
			doc:  "<a b=\"x\ty\r\nz&#9;w\" c='1\n2'/>",
			want: "<a b=\"x y z&#x9;w\" c=\"1 2\"></a>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, ids, err := parseXML([]byte(tt.doc))
			if err != nil {
				t.Fatalf("parseXML() error = %v", err)
			}
			e := root
			if tt.id != "" {
				e = ids[tt.id]
			}
			if got := string(canonical(e, nil)); got != tt.want {
				t.Errorf("canonical(%s) =\n%s\nwant\n%s", tt.name, got, tt.want)
			}
		})
	}
}
