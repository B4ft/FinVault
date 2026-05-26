package com.finvault.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Document Controller
 *
 * VULNERABILITY 4: SSRF - Server-Side Request Forgery
 * VULNERABILITY 5: XXE - XML External Entity Injection
 */
@Controller
@RequestMapping("/documents")
public class DocumentController {

    // -------------------------------------------------------------------------
    // DOCUMENTS LIST PAGE
    // -------------------------------------------------------------------------

    @GetMapping("")
    public String documentsPage(HttpServletRequest request, Model model) {
        model.addAttribute("username", request.getAttribute("username"));
        model.addAttribute("role", request.getAttribute("role"));
        model.addAttribute("userId", request.getAttribute("userId"));
        return "documents";
    }

    // -------------------------------------------------------------------------
    // SSRF - FETCH URL
    // -------------------------------------------------------------------------

    /**
     * VULNERABILITY: Server-Side Request Forgery (SSRF)
     * Fetches any URL provided by the user with no validation.
     *
     * Demo exploit:
     *   URL: http://localhost:8080/internal/admin-data
     *   URL: http://169.254.169.254/latest/meta-data/ (AWS metadata)
     *   URL: file:///etc/passwd
     *
     * The internal endpoint at /internal/admin-data is only accessible from localhost,
     * but SSRF lets external users reach it via the server.
     */
    @GetMapping("/fetch")
    public String fetchPage(HttpServletRequest request, Model model) {
        model.addAttribute("username", request.getAttribute("username"));
        model.addAttribute("role", request.getAttribute("role"));
        model.addAttribute("userId", request.getAttribute("userId"));
        return "documents";
    }

    @PostMapping("/fetch")
    @ResponseBody
    public ResponseEntity<?> fetchDocument(@RequestParam String url,
                                           HttpServletRequest request) {
        Map<String, Object> result = new HashMap<>();
        result.put("requestedUrl", url);

        try {
            // VULNERABILITY: No SSRF protection - fetches any URL
            URL targetUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setInstanceFollowRedirects(true);

            int statusCode = conn.getResponseCode();
            result.put("statusCode", statusCode);

            // Read response body
            InputStream is = (statusCode >= 200 && statusCode < 400)
                ? conn.getInputStream()
                : conn.getErrorStream();

            if (is != null) {
                StringBuilder sb = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    String line;
                    int lineCount = 0;
                    while ((line = reader.readLine()) != null && lineCount < 200) {
                        sb.append(line).append("\n");
                        lineCount++;
                    }
                }
                result.put("content", sb.toString());
                result.put("contentLength", sb.length());
            }

            result.put("success", true);
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            result.put("errorType", e.getClass().getName());
        }

        return ResponseEntity.ok(result);
    }

    // -------------------------------------------------------------------------
    // XXE - XML UPLOAD
    // -------------------------------------------------------------------------

    /**
     * VULNERABILITY: XML External Entity (XXE) Injection
     * DocumentBuilderFactory is not configured to disable external entities.
     *
     * Exploit - upload an XML file with:
     * <?xml version="1.0"?>
     * <!DOCTYPE foo [
     *   <!ENTITY xxe SYSTEM "file:///etc/passwd">
     * ]>
     * <statement>
     *   <data>&xxe;</data>
     * </statement>
     *
     * The parsed content is returned in the response, so file read output is visible.
     */
    @GetMapping("/upload-xml")
    public String uploadXmlPage(HttpServletRequest request, Model model) {
        model.addAttribute("username", request.getAttribute("username"));
        model.addAttribute("role", request.getAttribute("role"));
        model.addAttribute("userId", request.getAttribute("userId"));
        return "documents";
    }

    @PostMapping("/upload-xml")
    @ResponseBody
    public ResponseEntity<?> uploadXml(@RequestParam("file") MultipartFile file,
                                       HttpServletRequest request) {
        Map<String, Object> result = new HashMap<>();
        result.put("filename", file.getOriginalFilename());
        result.put("fileSize", file.getSize());

        try {
            // VULNERABILITY: XXE - external entities NOT disabled
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // Intentionally NOT setting these security features:
            // dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            // dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            // dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            // dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            // dbf.setXIncludeAware(false);
            // dbf.setExpandEntityReferences(false);

            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(file.getInputStream());
            doc.getDocumentElement().normalize();

            // Serialize parsed XML back to string (so XXE file read output is visible)
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");

            StringWriter sw = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(sw));
            String parsedXml = sw.toString();

            result.put("success", true);
            result.put("rootElement", doc.getDocumentElement().getTagName());
            result.put("parsedContent", parsedXml);
            result.put("message", "XML document processed successfully");

            // Extract text content for display
            StringBuilder textContent = new StringBuilder();
            extractTextContent(doc.getDocumentElement(), textContent, 0);
            result.put("extractedData", textContent.toString());

        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            result.put("errorType", e.getClass().getName());
            // Show partial output even on error (for XXE OOB exfiltration scenarios)
            result.put("note", "Parsing error - external entity resolution may have succeeded before error");
        }

        return ResponseEntity.ok(result);
    }

    private void extractTextContent(org.w3c.dom.Node node, StringBuilder sb, int depth) {
        String indent = "  ".repeat(depth);
        if (node.getNodeType() == org.w3c.dom.Node.ELEMENT_NODE) {
            sb.append(indent).append("<").append(node.getNodeName()).append(">");
            if (node.getTextContent() != null && !node.getTextContent().trim().isEmpty()
                    && !node.hasChildNodes()) {
                sb.append(node.getTextContent().trim());
            }
            sb.append("\n");

            org.w3c.dom.NodeList children = node.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                if (children.item(i).getNodeType() == org.w3c.dom.Node.ELEMENT_NODE) {
                    extractTextContent(children.item(i), sb, depth + 1);
                } else if (children.item(i).getNodeType() == org.w3c.dom.Node.TEXT_NODE) {
                    String text = children.item(i).getTextContent().trim();
                    if (!text.isEmpty()) {
                        sb.append(indent).append("  ").append(text).append("\n");
                    }
                }
            }
        }
    }
}
