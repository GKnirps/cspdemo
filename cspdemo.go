package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
)

func handleRequest(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("x-clacks-overhead", "GNU Terry Pratchett")

	sendCspParam := request.FormValue("send-csp")
	sendCsp := sendCspParam == "on"
	defaultSrcParam := request.FormValue("default-src")

	cspHeader := ""

	if sendCsp && defaultSrcParam != "" {
		cspHeader = fmt.Sprintf("report-uri /report; default-src %s;", defaultSrcParam)
		response.Header().Set("content-security-policy", cspHeader)
	}

	data := renderInfo{sendCsp, defaultSrcParam, cspHeader}

	renderPage(response, data)
}

type renderInfo struct {
	SendCsp    bool
	DefaultSrc string
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
// javascript, images
// checksum
// TODO: Readme-file
// link to https://content-security-policy.com/
// settings required in /etc/hosts

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
      </div>
      <div class="demo-local">
        <h3>This section uses css and script that is rendered in the header</h3>
        <div class="css-testarea">This text should be red</div>
      </div>
      <div class="demo-path-only">
        <h3>This section uses css and script that is loaded by a path relative to the document domain</h3>
        <div class="css-testarea">This text should be red</div>
      </div>
      <div class="demo-same-domain">
        <h3>This section uses css and script that is loaded from the domain "localhost"</h3>
        <div class="css-testarea">This text should be red</div>
      </div>
      <div class="demo-subdomain">
        <h3>This section uses css and script that is loaded from a the domain "sub.localhost"</h3>
        <div class="css-testarea">This text should be red</div>
      </div>
      <div class="demo-foreign-domain">
        <h3>This section uses css and script that is loaded from a the domain "unlocalhost"</h3>
        <div class="css-testarea">This text should be red</div>
      </div>
      <div class="demo-foreign-subdomain">
        <h3>This section uses css and script that is loaded from a the domain "sub.unlocalhost"</h3>
        <div class="css-testarea">This text should be red</div>
      </div>
    </div>
  </body>
</html>
`
