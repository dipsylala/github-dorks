"""Regex content tests — verify each pattern matches vulnerable code and
does not match safe equivalents.

Each parametrized case is a tuple of:
    (pattern_id, should_match: bool, code_snippet: str)
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Load all patterns from YAML files once at module import
# ---------------------------------------------------------------------------

_PATTERNS_DIR = Path(__file__).parent.parent / "config" / "patterns"

_PATTERN_MAP: dict[str, re.Pattern] = {}


def _load_patterns() -> None:
    for yaml_file in _PATTERNS_DIR.rglob("*.yaml"):
        with yaml_file.open(encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        for entry in doc.get("patterns", []):
            pid = entry.get("id")
            raw = entry.get("regex")
            if pid and raw:
                _PATTERN_MAP[pid] = re.compile(raw, re.MULTILINE)


_load_patterns()


def _match(pattern_id: str, code: str) -> bool:
    pat = _PATTERN_MAP[pattern_id]
    return pat.search(code) is not None


# ---------------------------------------------------------------------------
# Test cases  (pattern_id, should_match, snippet)
# ---------------------------------------------------------------------------

_CASES: list[tuple[str, bool, str]] = [

    # ------------------------------------------------------------------ #
    # Python — CWE-78  OS Command Injection
    # ------------------------------------------------------------------ #
    ("cmd_python_subprocess_shell_true", True, "subprocess.call(cmd, shell=True)"),
    ("cmd_python_subprocess_shell_true", True, "subprocess.run(cmd, shell=True)"),
    ("cmd_python_subprocess_shell_true", True, "subprocess.Popen(args, shell=True)"),
    ("cmd_python_subprocess_shell_true", False, "subprocess.run(['ls', '-la'])"),
    ("cmd_python_subprocess_shell_true", False, "# shell=True is dangerous"),
    ("cmd_python_os_system", True, "os.system(cmd)"),
    ("cmd_python_os_system", False, "posixpath.os_system_compat()"),
    ("cmd_python_os_popen", True, "os.popen(user_input)"),
    ("cmd_python_os_exec", True, "os.execvp('ls', args)"),
    ("cmd_python_os_exec", True, "os.execl('/bin/sh', args)"),
    ("cmd_python_os_exec", False, "os.path.exists('/tmp')"),

    # ------------------------------------------------------------------ #
    # Python — CWE-89  SQL Injection
    # ------------------------------------------------------------------ #
    ("sqli_python_execute_format", True, 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")'),
    ("sqli_python_execute_format", True, '.execute("SELECT * FROM t WHERE x=" % (val,))'),
    ("sqli_python_execute_format", False, 'cursor.execute("SELECT * FROM users WHERE id=?", (uid,))'),
    ("sqli_python_execute_concat", True, 'cursor.execute("SELECT * FROM t WHERE x=" + user)'),
    ("sqli_python_execute_concat", False, 'cursor.execute("SELECT 1")'),
    ("sqli_python_raw_sql_request", True, 'query = "SELECT * FROM t WHERE " + request.GET["q"]'),
    ("sqli_python_text_interpolated", True, 'db.execute(text(f"SELECT * FROM users WHERE name={name}"))'),
    ("sqli_python_text_interpolated", False, 'db.execute(text("SELECT 1"))'),

    # ------------------------------------------------------------------ #
    # Python — CWE-22  Path Traversal
    # ------------------------------------------------------------------ #
    ("path_python_open_request", True, "open(request.GET['file'])"),
    ("path_python_open_request", True, "open(filename)"),
    ("path_python_open_request", False, 'open("config.txt")'),
    ("path_python_send_file_var", True, "send_file(request.args.get('path'))"),
    ("path_python_os_path_join_request", True, "os.path.join(base, request.args['f'])"),
    ("path_python_os_path_join_request", False, 'os.path.join("/tmp", "file.txt")'),

    # ------------------------------------------------------------------ #
    # Python — CWE-502  Deserialization
    # ------------------------------------------------------------------ #
    ("deser_python_pickle_loads", True, "pickle.loads(data)"),
    ("deser_python_pickle_loads", True, "pickle.load(fp)"),
    ("deser_python_pickle_unpickler", True, "pickle.Unpickler(stream)"),
    ("deser_python_yaml_load_unsafe", True, "yaml.load(stream)"),
    ("deser_python_yaml_load_unsafe", True, "yaml.load(data, )"),
    ("deser_python_yaml_load_unsafe", False, "yaml.load(data, Loader=yaml.SafeLoader)"),
    ("deser_python_yaml_load_unsafe", False, "yaml.load(stream, Loader=yaml.FullLoader)"),
    ("deser_python_yaml_load_unsafe", False, "yaml.safe_load(stream)"),
    ("deser_python_marshal_loads", True, "marshal.loads(data)"),

    # ------------------------------------------------------------------ #
    # Python — CWE-95  Code Injection
    # ------------------------------------------------------------------ #
    ("codeinjection_python_eval_request", True, "eval(request.body)"),
    ("codeinjection_python_eval_request", False, 'eval("1 + 1")'),
    ("codeinjection_python_exec_request", True, "exec(request.data)"),
    ("codeinjection_python_eval_fstring", True, 'eval(f"result = {expr}")'),
    ("codeinjection_python_eval_fstring", False, 'eval("1 + 1")'),
    ("codeinjection_python_eval_variable", True, "eval(user_code)"),
    ("codeinjection_python_eval_variable", False, 'eval("1 + 1")'),
    ("codeinjection_python_eval_variable", False, "eval(b'bytes literal')"),
    ("codeinjection_python_jinja2_from_string", True, "Template . from_string(user_input)"),
    ("codeinjection_python_jinja2_from_string", False, 'Template.from_string("hello")'),

    # ------------------------------------------------------------------ #
    # Python — CWE-295  Cert Validation
    # ------------------------------------------------------------------ #
    ("ssl_python_cert_none", True, "ctx.verify_mode = ssl.CERT_NONE"),
    ("ssl_python_check_hostname_false", True, "ctx.check_hostname = False"),
    ("ssl_python_check_hostname_false", False, "ctx.check_hostname = True"),
    ("ssl_python_requests_verify_false", True, "requests.get(url, verify=False)"),
    ("ssl_python_requests_verify_false", False, "requests.get(url, verify=True)"),
    ("ssl_python_requests_verify_false", False, "# verify=False is bad"),
    ("ssl_python_httpx_verify_false", True, "httpx.get(url, verify=False)"),
    ("ssl_python_unverified_context_override", True,
     "ssl._create_default_https_context = ssl._create_unverified_context"),

    # ------------------------------------------------------------------ #
    # Python — CWE-327  Weak Crypto
    # ------------------------------------------------------------------ #
    ("crypto_python_hashlib_md5", True, "hashlib.md5(data)"),
    ("crypto_python_hashlib_sha1", True, "hashlib.sha1(data)"),
    ("crypto_python_hashlib_new_weak", True, "hashlib.new('md5', data)"),
    ("crypto_python_hashlib_new_weak", True, 'hashlib.new("sha1")'),
    ("crypto_python_hashlib_new_weak", False, 'hashlib.new("sha256")'),

    # ------------------------------------------------------------------ #
    # Python — CWE-611  XXE
    # ------------------------------------------------------------------ #
    ("xxe_python_elementtree_parse", True, "ET.parse(filename)"),
    ("xxe_python_elementtree_parse", True, "ElementTree.parse(fp)"),
    ("xxe_python_elementtree_fromstring", True, "ET.fromstring(data)"),
    ("xxe_python_minidom_parse", True, "minidom.parse(fp)"),
    ("xxe_python_minidom_parsestring", True, "minidom.parseString(data)"),
    ("xxe_python_lxml_parse", True, "lxml.etree.parse(fp)"),
    ("xxe_python_saxutils_parse", True, "xml.sax.parse(fp, handler)"),

    # ------------------------------------------------------------------ #
    # JavaScript — CWE-78  OS Command Injection
    # ------------------------------------------------------------------ #
    ("cmd_node_exec_var", True, "exec(cmd)"),
    ("cmd_node_exec_var", True, "exec(command)"),
    ("cmd_node_exec_var", True, "exec(req.body.cmd)"),
    ("cmd_node_exec_var", False, 'exec("ls -la")'),
    ("cmd_node_exec_var", False, "exec('whoami')"),
    ("cmd_node_execsync_var", True, "execSync(cmd)"),
    ("cmd_node_execsync_var", True, "execSync(`ls ${dir}`)"),
    ("cmd_node_execsync_var", False, 'execSync("ls -la")'),
    ("cmd_node_spawn_shell", True, "spawn('sh', args, { shell: true })"),
    ("cmd_node_spawn_shell", False, "spawn('ls', ['-la'])"),
    ("cmd_node_template_literal_exec", True, "exec(`rm -rf ${userPath}`)"),
    ("cmd_node_template_literal_exec", False, "exec(`ls -la`)"),

    # ------------------------------------------------------------------ #
    # JavaScript — CWE-89  SQL Injection
    # ------------------------------------------------------------------ #
    ("sqli_node_query_template_literal", True, "db.query(`SELECT * FROM t WHERE id=${req.params.id}`)"),
    ("sqli_node_query_template_literal", False, "db.query('SELECT 1')"),
    ("sqli_node_query_concat", True, 'db.query("SELECT * FROM t WHERE id=" + id)'),
    ("sqli_node_query_concat", False, "db.query('SELECT 1')"),
    ("sqli_node_knex_raw_var", True, "knex.raw(`SELECT * FROM t WHERE id=${id}`)"),
    ("sqli_node_sequelize_query_var", True, "sequelize.query(`SELECT * FROM t WHERE id=${id}`)"),

    # ------------------------------------------------------------------ #
    # JavaScript — CWE-79  XSS
    # ------------------------------------------------------------------ #
    ("xss_node_innerhtml_var", True, "el.innerHTML = req.body.content"),
    ("xss_node_innerhtml_var", True, "el.innerHTML = input"),
    ("xss_node_innerhtml_var", False, 'el.innerHTML = "<b>safe</b>"'),
    ("xss_node_document_write_var", True, "document.write(req.query.msg)"),
    ("xss_express_res_send_request", True, "res.send(req.body.data)"),
    ("xss_express_res_send_request", False, 'res.send("Hello world")'),

    # ------------------------------------------------------------------ #
    # JavaScript — CWE-95  Code Injection
    # ------------------------------------------------------------------ #
    ("codeinjection_js_eval_location", True, "eval(window.location)"),
    ("codeinjection_js_eval_location", True, "eval(location)"),
    ("codeinjection_js_eval_urlsearchparams", True, "eval(urlParams)"),
    ("codeinjection_js_eval_urlsearchparams", True, "eval(searchParams)"),
    ("codeinjection_js_eval_req_body", True, "eval(req.body)"),
    ("codeinjection_js_eval_req_body", True, "eval(request.query.code)"),
    ("codeinjection_js_eval_req_body", False, 'eval("1 + 1")'),
    ("codeinjection_js_new_function_req", True, "new Function(req.body.code)"),
    ("codeinjection_js_new_function_param", True, "new Function(location.search)"),
    ("codeinjection_js_settimeout_string_variable", True, "setTimeout(userCode, 1000)"),
    ("codeinjection_js_settimeout_string_variable", False, 'setTimeout("doSomething()", 1000)'),
    ("codeinjection_js_settimeout_string_variable", False, "setTimeout(() => {}, 1000)"),
    ("codeinjection_js_vm_runincontext", True, "vm.runInThisContext(userCode)"),
    ("codeinjection_js_vm_runincontext", True, "vm.runInContext(userCode, ctx)"),
    ("codeinjection_js_vm_runincontext", False, 'vm.runInThisContext("1 + 1")'),

    # ------------------------------------------------------------------ #
    # JavaScript — CWE-327  Weak Crypto
    # ------------------------------------------------------------------ #
    ("crypto_js_createhash_md5", True, "crypto.createHash('md5')"),
    ("crypto_js_createhash_md5", False, "crypto.createHash('sha256')"),
    ("crypto_js_createhash_sha1", True, 'crypto.createHash("sha1")'),
    ("crypto_js_createhash_sha1", False, 'crypto.createHash("sha256")'),
    ("crypto_js_createcipher_des", True, "crypto.createCipher('des', key)"),
    ("crypto_js_createcipher_des", True, "crypto.createCipheriv('rc4', key, iv)"),
    ("crypto_js_createcipher_des", False, "crypto.createCipher('aes-256-cbc', key)"),
    ("crypto_js_md5_library", True, "require('md5')"),
    ("crypto_js_md5_library", False, "require('md5-stream')"),

    # ------------------------------------------------------------------ #
    # JavaScript — CWE-319  Cleartext Transmission
    # ------------------------------------------------------------------ #
    ("cleartext_js_insecure_websocket", True, "new WebSocket('ws://api.example.com/ws')"),
    ("cleartext_js_insecure_websocket", False, "new WebSocket('wss://api.example.com/ws')"),
    ("cleartext_js_insecure_websocket", False, "new WebSocket('ws://localhost:3000')"),
    ("cleartext_js_http_fetch", True, "fetch('http://api.example.com/data')"),
    ("cleartext_js_http_fetch", False, "fetch('https://api.example.com/data')"),
    ("cleartext_js_axios_http", True, "axios.get('http://api.example.com')"),
    ("cleartext_js_axios_http", False, "axios.get('https://api.example.com')"),
    ("cleartext_js_xmlhttprequest_http", True, "xhr.open('GET', 'http://api.example.com/data')"),
    ("cleartext_js_xmlhttprequest_http", False, "xhr.open('GET', 'https://api.example.com/data')"),

    # ------------------------------------------------------------------ #
    # JavaScript — CWE-22  Path Traversal
    # ------------------------------------------------------------------ #
    ("path_node_fs_readfile_var", True, "fs.readFile(req.params.name, cb)"),
    ("path_node_fs_readfile_var", True, "fs.readFileSync(filename)"),
    ("path_node_fs_readfile_var", False, 'fs.readFile("config.json", cb)'),
    ("path_node_path_join_request", True, "path.join(base, req.query.file)"),
    ("path_node_path_join_request", False, "path.join('/tmp', 'file.txt')"),
    ("path_node_res_sendfile_var", True, "res.sendFile(req.params.file)"),
    ("path_node_res_sendfile_var", False, 'res.sendFile("index.html")'),
    ("path_node_fs_unlink_var", True, "fs.unlink(req.body.path, cb)"),

    # ------------------------------------------------------------------ #
    # PHP — CWE-78  OS Command Injection
    # ------------------------------------------------------------------ #
    ("cmd_php_exec", True, "exec($cmd, $output)"),
    ("cmd_php_exec", True, "exec('whoami')"),
    ("cmd_php_system", True, "system($input)"),
    ("cmd_php_passthru", True, "passthru($cmd)"),
    ("cmd_php_shell_exec", True, "shell_exec($cmd)"),
    ("cmd_php_backtick", True, "`rm -rf $path`"),
    ("cmd_php_backtick", False, "`ls -la`"),
    ("cmd_php_proc_open", True, "proc_open($cmd, $desc, $pipes)"),

    # ------------------------------------------------------------------ #
    # PHP — CWE-79  XSS
    # ------------------------------------------------------------------ #
    ("xss_php_echo_get", True, "echo $_GET['name'];"),
    ("xss_php_echo_post", True, "echo $_POST['email'];"),
    ("xss_php_echo_request", True, "echo $_REQUEST['q'];"),
    ("xss_php_echo_cookie", True, "echo $_COOKIE['session'];"),
    ("xss_php_print_superglobal", True, "print $_GET['msg'];"),
    ("xss_php_printf_superglobal", True, "printf('%s', $_GET['name'])"),

    # ------------------------------------------------------------------ #
    # PHP — CWE-89  SQL Injection
    # ------------------------------------------------------------------ #
    ("sqli_php_mysql_query", True, "mysql_query(\"SELECT * FROM t WHERE id='$id'\")"),
    ("sqli_php_mysql_query", False, 'mysql_query("SELECT 1")'),
    ("sqli_php_mysqli_query", True, "mysqli_query($conn, $sql)"),
    ("sqli_php_pg_query", True, "pg_query($conn, $query)"),
    ("sqli_php_pdo_query_concat", True, "$pdo->query($sql . $input)"),
    ("sqli_php_sprintf_sql", True, "sprintf(\"SELECT * FROM t WHERE id=%d\", $id)"),

    # ------------------------------------------------------------------ #
    # PHP — CWE-94  Code Injection
    # ------------------------------------------------------------------ #
    ("codeinjection_php_eval", True, "eval($code);"),
    ("codeinjection_php_eval", True, "eval('echo 1;');"),
    ("codeinjection_php_preg_replace_eval", True, "preg_replace('/pattern/e', $replacement, $subject)"),
    ("codeinjection_php_preg_replace_eval", False, "preg_replace('/pattern/i', $repl, $str)"),
    ("codeinjection_php_assert_variable", True, "assert($condition)"),
    ("codeinjection_php_assert_variable", False, "assert(true)"),
    ("codeinjection_php_create_function", True, "create_function('$x', 'return $x*2;')"),
    ("codeinjection_php_eval_superglobal", True, "eval($_GET['code'])"),
    ("codeinjection_php_eval_superglobal", True, "eval($_POST['payload'])"),

    # ------------------------------------------------------------------ #
    # PHP — CWE-502  Deserialization
    # ------------------------------------------------------------------ #
    ("deser_php_unserialize", True, "unserialize($data)"),
    ("deser_php_unserialize", False, "unserialize('serialized_string')"),
    ("deser_php_unserialize_request", True, "unserialize($_GET['data'])"),
    ("deser_php_unserialize_request", True, "unserialize($_COOKIE['sess'])"),

    # ------------------------------------------------------------------ #
    # PHP — CWE-611  XXE
    # ------------------------------------------------------------------ #
    ("xxe_php_libxml_entity_loader_enabled", True, "libxml_disable_entity_loader(false)"),
    ("xxe_php_libxml_entity_loader_enabled", False, "libxml_disable_entity_loader(true)"),
    ("xxe_php_libxml_noent_flag", True, "simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT)"),
    ("xxe_php_simplexml_load_string", True, "simplexml_load_string($xml)"),
    ("xxe_php_simplexml_load_file", True, "simplexml_load_file($path)"),
    ("xxe_php_domdocument_loadxml", True, "$dom->loadXML($input)"),
    ("xxe_php_xmlparser_create", True, "xml_parser_create()"),

    # ------------------------------------------------------------------ #
    # PHP — CWE-98  File Inclusion
    # ------------------------------------------------------------------ #
    ("file_php_include_var", True, "include($page)"),
    ("file_php_include_once_var", True, "include_once($path)"),
    ("file_php_require_var", True, "require($module)"),
    ("file_php_require_once_var", True, "require_once($file)"),
    ("file_php_fopen_var", True, "fopen($filename, 'r')"),
    ("file_php_fopen_var", False, 'fopen("data.txt", "r")'),
    ("file_php_file_get_contents_var", True, "file_get_contents($path)"),
    ("file_php_readfile_var", True, "readfile($path)"),

    # ------------------------------------------------------------------ #
    # C# — CWE-78  OS Command Injection
    # ------------------------------------------------------------------ #
    ("cmdi_dotnet_process_start_variable", True, "Process.Start(command)"),
    ("cmdi_dotnet_process_start_variable", True, "Process.Start(userInput)"),
    ("cmdi_dotnet_process_start_variable", False, 'Process.Start("notepad.exe")'),
    ("cmdi_dotnet_processstartinfo_filename_var", True, "StartInfo.FileName = command"),
    ("cmdi_dotnet_processstartinfo_filename_var", False, 'StartInfo.FileName = "notepad.exe"'),
    ("cmdi_dotnet_processstartinfo_arguments_var", True, "StartInfo.Arguments = args"),
    ("cmdi_dotnet_processstartinfo_arguments_var", False, 'StartInfo.Arguments = "/c dir"'),
    ("cmdi_dotnet_processstartinfo_constructor_var", True, "new ProcessStartInfo(command)"),
    ("cmdi_dotnet_processstartinfo_constructor_var", False, 'new ProcessStartInfo("cmd.exe")'),
    ("cmdi_dotnet_cmd_shell_execute", True,
     'new ProcessStartInfo("cmd.exe") { Arguments = "/c " + userInput }'),

    # ------------------------------------------------------------------ #
    # C# — CWE-79  XSS
    # ------------------------------------------------------------------ #
    ("xss_dotnet_response_write_request", True, "Response.Write(Request[\"name\"])"),
    ("xss_dotnet_html_raw", True, "@Html.Raw(model.Content)"),
    ("xss_dotnet_html_raw_request", True, "Html.Raw(Request.QueryString[\"msg\"])"),
    ("xss_dotnet_html_raw_request", False, 'Html.Raw(Html.Encode(input))'),
    ("xss_dotnet_mvchtmlstring_create", True, "MvcHtmlString.Create(content)"),
    ("xss_dotnet_htmlstring_create", True, "new HtmlString(content)"),
    ("xss_dotnet_innerhtml_assignment", True, "div.InnerHtml = userContent"),
    ("xss_dotnet_innerhtml_assignment", False, 'div.InnerHtml = "<b>safe</b>"'),

    # ------------------------------------------------------------------ #
    # C# — CWE-89  SQL Injection
    # ------------------------------------------------------------------ #
    ("sqli_dotnet_sqlcommand_string_format", True, 'new SqlCommand(string.Format("SELECT * FROM t WHERE id={0}", id))'),
    ("sqli_dotnet_sqlcommand_concat", True, 'new SqlCommand("SELECT * FROM t WHERE id=" + userId)'),
    ("sqli_dotnet_sqlcommand_interpolated", True, 'new SqlCommand($"SELECT * FROM t WHERE id={userId}")'),
    ("sqli_dotnet_sqlcommand_interpolated", False, 'new SqlCommand("SELECT * FROM t WHERE id=@id")'),
    ("sqli_dotnet_entityframework_fromsql", True, 'context.Users.FromSql($"SELECT * FROM users WHERE id={userId}")'),
    ("sqli_dotnet_entityframework_fromsql", True, 'context.Database.ExecuteSqlRaw("DELETE FROM t WHERE id=" + id)'),

    # ------------------------------------------------------------------ #
    # C# — CWE-209  Information Disclosure
    # ------------------------------------------------------------------ #
    ("infodisclosure_dotnet_developer_exception_page", True, "app.UseDeveloperExceptionPage()"),
    ("infodisclosure_dotnet_response_write_exception", True, "Response.Write(ex.Message)"),
    ("infodisclosure_dotnet_response_write_exception", True, "Response.Write(exception.StackTrace)"),
    ("infodisclosure_dotnet_return_exception_message", True, "return ex.Message"),
    ("infodisclosure_dotnet_return_stacktrace", True, "var trace = ex.StackTrace"),
    ("infodisclosure_dotnet_content_exception", True, "return Content(ex.Message)"),
    ("infodisclosure_dotnet_content_exception", True, "return Ok(exception.ToString())"),

    # ------------------------------------------------------------------ #
    # C# — CWE-601  Open Redirect
    # ------------------------------------------------------------------ #
    ("redirect_dotnet_response_redirect_request", True, "Response.Redirect(Request[\"returnUrl\"])"),
    ("redirect_dotnet_redirect_variable", True, "return Redirect(returnUrl)"),
    ("redirect_dotnet_redirect_variable", True, "return RedirectPermanent(url)"),
    ("redirect_dotnet_redirect_variable", False, 'return Redirect("/home")'),
    ("redirect_dotnet_redirect_querystring", True, "Redirect(Request.QueryString[\"next\"])"),
    ("redirect_dotnet_redirect_form_value", True, "Redirect(Request.Form[\"returnUrl\"])"),
    ("redirect_dotnet_localredirect_no_validation", True, "return LocalRedirect(returnUrl)"),
    ("redirect_dotnet_localredirect_no_validation", False, 'return LocalRedirect("/home/index")'),

    # ------------------------------------------------------------------ #
    # C# — CWE-502  Deserialization
    # ------------------------------------------------------------------ #
    ("deser_dotnet_binaryformatter", True, "var bf = new BinaryFormatter()"),
    ("deser_dotnet_typenamehanding_all", True, "TypeNameHandling.All"),
    ("deser_dotnet_losformatter", True, "new LosFormatter()"),
    ("deser_dotnet_xmlserializer_var", True, "new XmlSerializer(type)"),
    ("deser_dotnet_xmlserializer_var", True, "new XmlSerializer(t)"),
    # typeof with a hardcoded type — low severity but pattern still flags it
    ("deser_dotnet_xmlserializer_var", True, "new XmlSerializer(typeof(MyClass))"),
    ("deser_dotnet_xmlserializer_var", False, 'new XmlSerializer("string")'),

    # ------------------------------------------------------------------ #
    # Java — CWE-78  OS Command Injection
    # ------------------------------------------------------------------ #
    ("cmd_java_runtime_exec", True, "Runtime.getRuntime().exec(cmd)"),
    ("cmd_java_processbuilder_var", True, "new ProcessBuilder(command)"),
    ("cmd_java_processbuilder_var", True, "new ProcessBuilder(args)"),
    ("cmd_java_processbuilder_add", True, 'new ProcessBuilder(cmds); pb.add(request.getParameter("cmd"))'),
    ("cmd_java_processbuilder_add", False, 'list.add("normal item")'),

    # ------------------------------------------------------------------ #
    # Java — CWE-89  SQL Injection
    # ------------------------------------------------------------------ #
    ("sqli_java_statement_concat", True, 'stmt.executeQuery("SELECT * FROM users WHERE name=" + name)'),
    ("sqli_java_statement_execute_concat", True, 'stmt.execute("DELETE FROM t WHERE id=" + userId)'),
    ("sqli_java_createquery_concat", True, 'em.createQuery("SELECT u FROM User u WHERE u.name=" + name)'),
    ("sqli_java_createnativequery_concat", True, 'em.createNativeQuery("SELECT * FROM users WHERE id=" + id)'),

    # ------------------------------------------------------------------ #
    # Java — CWE-79  XSS
    # ------------------------------------------------------------------ #
    ("xss_java_response_writer_getparam", True, 'response.getWriter().write(request.getParameter("msg"))'),
    ("xss_java_out_print_getparam", True, 'out.print(request.getParameter("name"))'),
    ("xss_java_string_format_html", True, 'String.format("<b>%s</b>", request.getParameter("name"))'),
    ("xss_java_response_getwriter_variable", True, "response.getWriter().println(userInput)"),
    ("xss_java_response_getwriter_variable", False, 'response.getWriter().println("Hello world")'),

    # ------------------------------------------------------------------ #
    # Java — CWE-502  Deserialization
    # ------------------------------------------------------------------ #
    ("deser_java_objectinputstream", True, "new ObjectInputStream(socket.getInputStream())"),
    ("deser_java_readobject",  True, "Object obj = ois.readObject()"),
    ("deser_java_xmldecoder",  True, "XMLDecoder decoder = new XMLDecoder(stream)"),
    ("deser_java_jackson_enable_default_typing", True, "mapper.enableDefaultTyping()"),
    ("deser_java_jackson_activate_default_typing", True, "mapper.activateDefaultTyping(ptv)"),
    ("deser_java_snakeyaml_constructor", True, "Yaml yaml = new Yaml()"),
    ("deser_java_xstream_fromxml", True, "Object obj = xstream.fromXML(xml)"),
    ("deser_java_kryo_readobject", True, "User u = kryo.readObject(input, User.class)"),

    # ------------------------------------------------------------------ #
    # Java — CWE-611  XXE
    # ------------------------------------------------------------------ #
    ("xxe_java_documentbuilderfactory_new", True, "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance()"),
    ("xxe_java_saxparserfactory_new", True, "SAXParserFactory spf = SAXParserFactory.newInstance()"),
    ("xxe_java_xmlinputfactory_external_entities", True, 'xif.setProperty("javax.xml.stream.isSupportingExternalEntities", true)'),
    ("xxe_java_xmlinputfactory_external_entities", False, 'xif.setProperty("javax.xml.stream.isSupportingExternalEntities", false)'),
    ("xxe_java_expand_entity_refs", True, "dbf.setExpandEntityReferences(true)"),
    ("xxe_java_expand_entity_refs", False, "dbf.setExpandEntityReferences(false)"),
    ("xxe_java_transformerfactory_new", True, "TransformerFactory tf = TransformerFactory.newInstance()"),

    # ------------------------------------------------------------------ #
    # Java — CWE-327  Weak Crypto
    # ------------------------------------------------------------------ #
    ("crypto_java_messagedigest_md5", True, 'MessageDigest.getInstance("MD5")'),
    ("crypto_java_messagedigest_sha1", True, 'MessageDigest.getInstance("SHA-1")'),
    ("crypto_java_messagedigest_sha1", True, 'MessageDigest.getInstance("SHA1")'),
    ("crypto_java_messagedigest_sha1", False, 'MessageDigest.getInstance("SHA-256")'),
    ("crypto_java_cipher_des", True, 'Cipher.getInstance("DES/CBC/PKCS5Padding")'),
    ("crypto_java_cipher_des", True, 'Cipher.getInstance("DES")'),
    ("crypto_java_cipher_des", False, 'Cipher.getInstance("AES/CBC/PKCS5Padding")'),
    ("crypto_java_cipher_ecb_mode", True, 'Cipher.getInstance("AES/ECB/PKCS5Padding")'),
    ("crypto_java_cipher_ecb_mode", False, 'Cipher.getInstance("AES/CBC/PKCS5Padding")'),
    ("crypto_java_rsa_no_oaep", True, 'Cipher.getInstance("RSA/ECB/PKCS1Padding")'),
    ("crypto_java_rsa_no_oaep", True, 'Cipher.getInstance("RSA/ECB/NoPadding")'),
    ("crypto_java_rsa_no_oaep", False, 'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")'),

    # ------------------------------------------------------------------ #
    # Java — CWE-22  Path Traversal
    # ------------------------------------------------------------------ #
    ("path_java_fileinputstream_var", True, "new FileInputStream(request.getParameter(\"file\"))"),
    ("path_java_paths_get_var", True, "Paths.get(request.getParameter(\"path\"))"),
    ("path_java_file_constructor_var", True, "new File(request.getParameter(\"name\"))"),

    # ------------------------------------------------------------------ #
    # Java — CWE-918  SSRF
    # ------------------------------------------------------------------ #
    ("ssrf_java_url_openconnection_var", True, "new URL(target).openConnection()"),
    ("ssrf_java_url_openstream_var", True, "new URL(userInput).openStream()"),
    ("ssrf_java_httpclient_send_var", True, "HttpRequest.newBuilder(URI.create(url)).build()"),
    ("ssrf_java_resttemplate_var", True, "restTemplate.getForObject(endpoint, String.class)"),
]


# ---------------------------------------------------------------------------
# Parametrized test
# ---------------------------------------------------------------------------

def _case_id(case: tuple) -> str:
    pid, should_match, snippet = case
    polarity = "match" if should_match else "no_match"
    # Truncate snippet for readable IDs
    short = snippet[:40].replace("\n", " ")
    return f"{pid}[{polarity}]:{short}"


@pytest.mark.parametrize("pattern_id,should_match,snippet", _CASES, ids=[
    _case_id(c) for c in _CASES
])
def test_pattern_content(pattern_id: str, should_match: bool, snippet: str) -> None:
    assert pattern_id in _PATTERN_MAP, f"Pattern '{pattern_id}' not found in loaded patterns"
    result = _match(pattern_id, snippet)
    if should_match:
        assert result, (
            f"Pattern '{pattern_id}' should match but did not.\n"
            f"  regex:   {_PATTERN_MAP[pattern_id].pattern!r}\n"
            f"  snippet: {snippet!r}"
        )
    else:
        assert not result, (
            f"Pattern '{pattern_id}' should NOT match but did (false positive).\n"
            f"  regex:   {_PATTERN_MAP[pattern_id].pattern!r}\n"
            f"  snippet: {snippet!r}"
        )
