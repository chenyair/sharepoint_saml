import 'dart:io';
import 'package:xml/xml.dart';
import 'package:http/http.dart' as http;
import 'package:sharepoint_saml/xml_security_token_body.dart';

class SharepointAuth {
  const SharepointAuth(
      {required this.username, required this.password, required this.domain});

  final String securityTokenEndpoint =
      'https://login.microsoftonline.com/extSTS.srf';

  final String domain;

  final String username;
  final String password;

  Future<AuthHeadersResposne> auth() async {
    final securityToken = await _getSecurityToken();
    final cookiesString = await _getCookiesString(securityToken);
    return AuthHeadersResposne(cookie: cookiesString);
  }

  Future<String> _getSecurityToken() async {
    final securityTokenUri = Uri.parse(securityTokenEndpoint);
    final http.Response response = await http.post(
      securityTokenUri,
      headers: {
        HttpHeaders.connectionHeader: 'application/soap+xml;charset=utf-8',
      },
      body: getXMLSecurityBody(username, password, _sharepointUrl),
    );

    final responseDocument = XmlDocument.parse(response.body);

    final securityTokenNode =
        responseDocument.findAllElements("wsse:BinarySecurityToken").first;

    return securityTokenNode.innerText;
  }

  Future<String> _getCookiesString(String securityToken) async {
    final cookiesUri = Uri.parse(_sharepointUrl);
    HttpClient client = new HttpClient();
    HttpClientRequest clientRequest = await client.postUrl(cookiesUri);

    clientRequest.headers.add(
      HttpHeaders.contentTypeHeader,
      'application/x-www-form-urlencoded',
    );
    clientRequest.write(securityToken);

    HttpClientResponse clientResponse = await clientRequest.close();

    final List<Cookie> authCookies = clientResponse.cookies
        .where(
          (cookie) => cookie.name == 'rtFa' || cookie.name == 'FedAuth',
        )
        .toList();

    return authCookies.fold<String>(
      '',
      (cookieString, cookie) => '${cookie.name}=${cookie.value};$cookieString',
    );
  }

  String get _sharepointUrl =>
      'https://$domain.sharepoint.com/_forms/default.aspx?wa=wsignin1.0';
}

class AuthHeadersResposne {
  final String cookie;

  const AuthHeadersResposne({required this.cookie});

  Map<String, dynamic> toMap() {
    return {'Cookie': cookie};
  }
}
