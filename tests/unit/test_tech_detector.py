from reconx.modules.tech_detector import TechDetector


class TestTechDetector:
    def test_wordpress_via_header(self) -> None:
        headers = {"Link": '<http://example.com/wp-json/>; rel="https://api.w.org/"'}
        findings = TechDetector.detect(headers, "")
        names = {f.title for f in findings}
        assert "WordPress" in names

    def test_react_via_html(self) -> None:
        html = '<div id="root" data-reactroot=""></div>'
        findings = TechDetector.detect({}, html)
        names = {f.title for f in findings}
        assert "React" in names

    def test_no_match(self) -> None:
        findings = TechDetector.detect({}, "<html><body>plain</body></html>")
        assert findings == []

    def test_nginx_via_header(self) -> None:
        headers = {"Server": "nginx/1.20.1"}
        findings = TechDetector.detect(headers, "")
        names = {f.title for f in findings}
        assert "Nginx" in names

    def test_apache_via_header(self) -> None:
        headers = {"Server": "Apache/2.4.41"}
        findings = TechDetector.detect(headers, "")
        names = {f.title for f in findings}
        assert "Apache" in names

    def test_php_via_header(self) -> None:
        headers = {"X-Powered-By": "PHP/8.1.0"}
        findings = TechDetector.detect(headers, "")
        names = {f.title for f in findings}
        assert "PHP" in names

    def test_angular_via_html(self) -> None:
        html = '<app-root ng-version="15.0.0"></app-root>'
        findings = TechDetector.detect({}, html)
        names = {f.title for f in findings}
        assert "Angular" in names
