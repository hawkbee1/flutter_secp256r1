import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_dart/agent_dart.dart';
import 'package:asn1lib/asn1lib.dart' as asn1lib;
import 'package:convert/convert.dart';
import 'package:flutter/material.dart';
import 'package:tuple/tuple.dart';
import 'package:x509/x509.dart' as x509;

import 'package:secp256r1/secp256r1.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _publicKey = 'Unknown';
  String _signed = 'Unknown';
  bool? _verified;
  String? _certificate, _sharedSecret, _decrypted;
  Tuple2<Uint8List, Uint8List>? _encrypted;

  final _payloadTEC = TextEditingController(text: 'Hello world');
  final _othersPublicKeyTEC = TextEditingController();

  String get alias => 'key2';

  String get _verifyPayload => _payloadTEC.text;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: ListView(
          children: [
            SelectableText('getTestPublicKey: $_publicKey\n'),
            SelectableText('certificate: $_certificate\n'),
            SizedBox(height: 16),
            SelectableText('sign: $_signed\n'),
            SelectableText('verify: $_verified\n'),
            SelectableText('sharedSecret: $_sharedSecret\n'),
            SelectableText('encrypted: $_encrypted\n'),
            SelectableText('decrypted: $_decrypted\n'),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 16),
              child: TextField(
                controller: _payloadTEC,
                decoration: const InputDecoration(
                  border: OutlineInputBorder(),
                  label: Text('Payload text field'),
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 16),
              child: TextField(
                controller: _othersPublicKeyTEC,
                decoration: const InputDecoration(
                  border: OutlineInputBorder(),
                  label: Text('Others Public Key (hex)'),
                ),
              ),
            ),
            ElevatedButton(
              onPressed: () {
                SecureP256.getTestPublicKey().then(
                  (r) => setState(() => _publicKey = hex.encode(r.rawKey)),
                );
              },
              child: const Text('getTestPublicKey'),
            ),
            ElevatedButton(
              onPressed: () {
                SecureP256.getCertificate(alias).then(
                  (r) => setState(() {
                    final decoded = base64Decode(r.toString());
                    final seq = asn1lib.ASN1Sequence.fromBytes(decoded);
                    final cert = x509.X509Certificate.fromAsn1(seq);
                    _certificate = cert.toString();
                  }),
                );
              },
              child: const Text('getCertificate'),
            ),
            ElevatedButton(
              onPressed: () {
                SecureP256.sign(
                  alias,
                  Uint8List.fromList(utf8.encode(_verifyPayload)),
                ).then((r) => setState(() => _signed = hex.encode(r)));
              },
              child: const Text('sign'),
            ),
            ElevatedButton(
              onPressed: () {
                SecureP256.verify(
                  Uint8List.fromList(utf8.encode(_verifyPayload)),
                  P256PublicKey.fromRaw(
                    Uint8List.fromList(hex.decode(_publicKey)),
                  ),
                  Uint8List.fromList(hex.decode(_signed)),
                ).then((r) => setState(() => _verified = r));
              },
              child: const Text('verify'),
            ),
            ElevatedButton(
              onPressed: () {
                SecureP256.getSharedSecret(
                  alias,
                  P256PublicKey.fromRaw(
                    Uint8List.fromList(
                      hex.decode(_othersPublicKeyTEC.text),
                    ),
                  ),
                ).then((r) => setState(() => _sharedSecret = hex.encode(r)));
              },
              child: const Text('getSharedSecret'),
            ),
            ElevatedButton(
              onPressed: () {
                SecureP256.encrypt(
                  sharedSecret: Uint8List.fromList(
                    hex.decode(_sharedSecret!),
                  ),
                  message: Uint8List.fromList(utf8.encode('Hello AstroX')),
                ).then((r) => setState(() => _encrypted = r));
              },
              child: const Text('Encrypt (FFI)'),
            ),
            ElevatedButton(
              onPressed: () {
                SecureP256.decrypt(
                  sharedSecret: Uint8List.fromList(
                    hex.decode(_sharedSecret!),
                  ),
                  iv: _encrypted!.item1,
                  cipher: _encrypted!.item2,
                ).then((r) => setState(() => _decrypted = utf8.decode(r)));
              },
              child: const Text('Decrypt (FFI)'),
            ),
          ],
        ),
      ),
    );
  }
}
