cspdemo
=======

Cspdemo is a small demo for the [Content Security Policy](https://content-security-policy.com/) HTTP header. It contains a server (written in go) that serves one page. On this page, there is a form where you can specify which content security policy header should be sent with the page. Below that are several sections with javascript and css from different sources, so you can see the effects of the CSP.

Cspdemo also supports reports of policy breaks which are sent to the server and logged on stdout.

The demo site is inherently ugly, because we can't reliably use styling because of changing content security policies.

License
-------
Cspdemo is published under GNU [General Public License](https://www.gnu.org/licenses/licenses.en.html#GPL).

Setup
-----

1. Download the repository and build the server with `go build`.
2. configure your /etc/hosts (or whatever configuration your OS uses) so that all of `localhost`, `sub.localhost`, `unlocalhost` and `sub.unlocalhost` point to your local machine. This is important to demonstrate resource delivery (and blocking) from different domains.
3. run cspdemo in the repository root directory (the directory is important, because the server needs to deliver some resources, such as css and javascript from the assets folder=
4. open `localhost:3000` in your browser.

Currently supported
--------------------

Cspdemo is a work in progress. Right now, the following features are supported:
- Loading (and displaying) of CSS and Javascript from different domains (including inline style/css)
- Setting the default-src attribute of the Content Security Policy header
- not sending a Content Security Policy Header at all
- displaying of the current Content Security Policy header in the HTML side (for reference)
- logging of reports of violations of the Content Security Policy in the stdout of the shell where the server is started

Planned features
----------------

- more different attributes of the Content Security Policy to be set in the page form
- more different resources (e.g. images)
