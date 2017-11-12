/*
cspdemo
© 2017 Guido Knips
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

func handleRequest(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("x-clacks-overhead", "GNU Terry Pratchett")

	sendCspParam := request.FormValue("send-csp")
	sendCsp := sendCspParam == "on"
	defaultSrcParam := request.FormValue("default-src")
	scriptSrcParam := request.FormValue("script-src")
	imgSrcParam := request.FormValue("img-src")
	styleSrcParam := request.FormValue("style-src")

	cspHeader := ""

	if sendCsp {
		cspHeader = createCspHeader(defaultSrcParam, scriptSrcParam, imgSrcParam, styleSrcParam)
		response.Header().Set("content-security-policy", cspHeader)
	}

	data := renderInfo{sendCsp, defaultSrcParam, scriptSrcParam, styleSrcParam, imgSrcParam, cspHeader}

	renderPage(response, data)
}

func createCspHeader(defaultSrc string, scriptSrc string, imgSrc string, styleSrc string) string {
	headerFields := make([]string, 0, 10)
	headerFields = append(headerFields, "report-uri /report;")

	headerFields = appendCspFieldIfNotEmpty(headerFields, "default-src", defaultSrc)
	headerFields = appendCspFieldIfNotEmpty(headerFields, "script-src", scriptSrc)
	headerFields = appendCspFieldIfNotEmpty(headerFields, "style-src", styleSrc)
	headerFields = appendCspFieldIfNotEmpty(headerFields, "img-src", imgSrc)

	return strings.Join(headerFields, " ")
}

func appendCspFieldIfNotEmpty(headerFields []string, fieldName string, fieldValue string) []string {
	if fieldValue != "" {
		return append(headerFields, fmt.Sprintf("%s %s;", fieldName, fieldValue))
	}
	return headerFields
}

type renderInfo struct {
	SendCsp    bool
	DefaultSrc string
	ScriptSrc  string
	StyleSrc   string
	ImgSrc     string
	CspHeader  string
}

func renderPage(response http.ResponseWriter, data renderInfo) {
	tmpl, err := template.New("Demo").Parse(pageTemplate)
	if err != nil {
		response.WriteHeader(500)
		fmt.Fprintf(response, "Internal Server Error")
	} else {
		tmpl.Execute(response, data)
	}
}

func cspReport(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		response.Header().Set("Allow", "POST")
		response.WriteHeader(405)
		response.Write([]byte{})
		return
	}
	bodyBuf := new(bytes.Buffer)
	_, err := bodyBuf.ReadFrom(request.Body)
	if err == nil {
		fmt.Println(bodyBuf.String())
		response.WriteHeader(200)
		response.Write([]byte{})
	} else {
		fmt.Println("Unable to read report body.")
		response.WriteHeader(500)
		fmt.Fprintf(response, "Internal Server Error")
	}
}

func main() {
	fs := http.FileServer(http.Dir("assets"))
	http.Handle("/assets/", http.StripPrefix("/assets", fs))
	http.HandleFunc("/report", cspReport)
	http.HandleFunc("/", handleRequest)

	http.ListenAndServe(":3000", nil)
}

// TODO: Examples:
// images
// checksum

const pageTemplate = `
<html>
  <head>
    <meta charset="UTF-8">
    <title>Experiment with the content security policy header</title>
    <style>
      .demo-local .css-testarea {color: red;}
    </style>
    <link rel="stylesheet" href="/assets/pathonly.css">
    <link rel="stylesheet" href="http://localhost:3000/assets/samedomain.css">
    <link rel="stylesheet" href="http://sub.localhost:3000/assets/subdomain.css">
    <link rel="stylesheet" href="http://unlocalhost:3000/assets/foreigndomain.css">
    <link rel="stylesheet" href="http://sub.unlocalhost:3000/assets/foreignsubdomain.css">
  </head>
  <body>
    <div class="settings-area">
      <form method="get">
        <div>
          <label>
            Send a content security policy header?
            <input name="send-csp" type="checkbox"{{if .SendCsp}} checked{{end}}/>
          </label>
        </div>
        <div>
          <label>
            default-src
            <input type="text" name="default-src" value="{{.DefaultSrc}}">
          </label>
        </div>
        <div>
          <label>
            script-src
            <input type="text" name="script-src" value="{{.ScriptSrc}}">
          </label>
        </div>
        <div>
          <label>
            style-src
            <input type="text" name="style-src" value="{{.StyleSrc}}">
          </label>
        </div>
        <div>
          <label>
            img-src
            <input type="text" name="img-src" value="{{.ImgSrc}}">
          </label>
        </div>
        <button type="submit">go</button>
      </form>
    </div>
    <div class="demo-area">
      {{if .CspHeader}}
        <p>You got a content security policy: {{.CspHeader}}</p>
      {{end}}
      <div class="demo-attributes">
        <h3>This section uses attribute style and inline code on onclick handlers</h3>
        <div class="css-testarea" style="color: red;">This text should be red</div>
        <div>
          <span id="demo-attributes-script">This text has <em>not</em> been altered by javascript</span>
          <script type="text/javascript">
            document.getElementById('demo-attributes-script').innerHTML = 'This text <em>has</em> been altered by javascript.'
          </script>
        </div>
      </div>
      <div class="demo-local">
        <h3>This section uses css that is rendered in the header</h3>
        <div class="css-testarea">This text should be red</div>
      </div>
      <div class="demo-path-only">
        <h3>This section uses css and script that is loaded by a path relative to the document domain</h3>
        <div class="css-testarea">This text should be red</div>
        <div>
          <span id="demo-path-only-script">This text has <em>not</em> been altered by javascript</span>
          <script type="text/javascript" src="/assets/pathonly.js"></script>
        </div>
        <div>
          An image of a check mark with a red frame should be displayed here:
          <img src="/assets/img.png" alt="check mark"/>
        </div>
      </div>
      <div class="demo-same-domain">
        <h3>This section uses css and script that is loaded from the domain "localhost"</h3>
        <div class="css-testarea">This text should be red</div>
        <div>
          <span id="demo-same-domain-script">This text has <em>not</em> been altered by javascript</span>
          <script type="text/javascript" src="http://localhost:3000/assets/samedomain.js"></script>
        </div>
        <div>
          An image of a check mark with a red frame should be displayed here:
          <img src="http://localhost:3000/assets/img.png" alt="check mark"/>
        </div>
      </div>
      <div class="demo-subdomain">
        <h3>This section uses css and script that is loaded from a the domain "sub.localhost"</h3>
        <div class="css-testarea">This text should be red</div>
        <div>
          <span id="demo-subdomain-script">This text has <em>not</em> been altered by javascript</span>
          <script type="text/javascript" src="http://sub.localhost:3000/assets/subdomain.js"></script>
        </div>
        <div>
          An image of a check mark with a red frame should be displayed here:
          <img src="http://sub.localhost:3000/assets/img.png" alt="check mark"/>
        </div>
      </div>
      <div class="demo-foreign-domain">
        <h3>This section uses css and script that is loaded from a the domain "unlocalhost"</h3>
        <div class="css-testarea">This text should be red</div>
        <div>
          <span id="demo-foreign-domain-script">This text has <em>not</em> been altered by javascript</span>
          <script type="text/javascript" src="http://unlocalhost:3000/assets/foreigndomain.js"></script>
        </div>
        <div>
          An image of a check mark with a red frame should be displayed here:
          <img src="http://unlocalhost:3000/assets/img.png" alt="check mark"/>
        </div>
      </div>
      <div class="demo-foreign-subdomain">
        <h3>This section uses css and script that is loaded from a the domain "sub.unlocalhost"</h3>
        <div class="css-testarea">This text should be red</div>
        <div>
          <span id="demo-foreign-subdomain-script">This text has <em>not</em> been altered by javascript</span>
          <script type="text/javascript" src="http://sub.unlocalhost:3000/assets/foreignsubdomain.js"></script>
        </div>
        <div>
          An image of a check mark with a red frame should be displayed here:
          <img src="http://sub.unlocalhost:3000/assets/img.png" alt="check mark"/>
        </div>
      </div>
    </div>
  </body>
</html>
`
