import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:http/http.dart' as http;
import '../routes/confirm_account_list.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

const String _secretKey = 'secret_key_hahaha_bjs';

class LoginSetting {
  final ConfirmAccountList confirmAccountList;

  LoginSetting({required this.confirmAccountList});
  //var account="";var passwd="";

  Router get router {
    final router = Router();
    var token;
    var listtoken;

    router.post('/', (Request request) async {
      // try {
      // var requestBody = await request.readAsString();
      // var loginData = jsonDecode(requestBody);
      var requestBody = await request.readAsString();
      var loginData = jsonDecode(requestBody);
      var loginCheck = 0;
      var account = loginData['account'];
      var passwd = loginData['passwd'];
      //print(account);
      //print(loginData);
      String? url = confirmAccountList.manageAddress.displayDbAddr;

      var response1Future = _ReqToWs4TotalPixel(url);
      var response3Future = _ReqToWs4LotInfo(url);
      var response2Future = _ReqToWs4LotType(url);
      var loginDataResult = _ReqToWs4Login(account, passwd, url);
      //_ReqToWs4Login(confirmAccountList.manageAddress.displayDbAddr);

      var response1 = await response1Future;
      var response3 = await response3Future;
      var response2 = await response2Future;
      var responseLogin = await loginDataResult;

      var responseLoginData = jsonDecode(responseLogin.body);
      //3 lots
      //2 tpye
      
      var resultSet4 = responseLoginData['results'][0]['resultSet'];
      for (var entry in resultSet4) {
        if (entry['account'] == account) {
          loginCheck = 1;
          if (entry['passwd'] == passwd) {
            loginCheck = 2;
            token = createJwt(account, 1);
            print('Generated Token: $token');
          }
        }
      }
      // listtoken = (jsonEncode({'token': token}), headers: {
      //   'Content-Type': 'application/json',
      // });
      listtoken = [{'token': token}];
      // 서버로부터의 응답 확인s
      if (response1.statusCode == 200 &&
          response2.statusCode == 200 &&
          response3.statusCode == 200 &&
          loginCheck == 2) {
        var responseData3 = jsonDecode(response3.body);
        var resultSet3 = responseData3['results'][0]['resultSet'];
        var responseData2 = jsonDecode(response2.body);
        var resultSet2 = responseData2['results'][0]['resultSet'];
        // print(resultSet2.length);
        // print(resultSet3);
        var check = List<dynamic>.filled(resultSet2.length, 0);
        for (int i = 0; i < resultSet3.length; i++) {
          check[resultSet3[i]['lot_type'] - 1]++;
        }
        Map<int, int> map = {
          for (var index in List.generate(check.length, (index) => index + 1))
            index: check[index - 1]
        };
        var responseData1 = jsonDecode(response1.body);
        // print('responseData4 : $responseLoginData');
        var resultSet1 = responseData1['results'][0]['resultSet'];
        // print(resultSet3[0]);
        
        var headers = {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*', // 허용할 오리진 설정
          'Access-Control-Allow-Methods':
              'GET, POST, PUT, DELETE, OPTIONS', // 허용할 메서드 설정
          'Access-Control-Allow-Headers':
              'Origin, Content-Type, X-Auth-Token' // 허용할 헤더 설정
        };
        // print(check);
        // print(check.length);
        // print(map);
        for(int i=1;i<=check.length;i++){
          // print(check[i-1]);
          if(check[i-1]==0){
            var body6 = { "transaction": [
              {"query": "UPDATE tb_lot_type SET (isUsed) = (:isUsed) WHERE uid = :uid",
              "values": {"isUsed": 0, "uid": i}
              }
            ]};
            await http.post(
              Uri.parse(url!),
              headers: headers,
              body: jsonEncode(body6),
            );
          }else{
            var body6 = { "transaction": [
              {"query": "UPDATE tb_lot_type SET (isUsed) = (:isUsed) WHERE uid = :uid",
              "values": {"isUsed": 1, "uid": i}
              }
            ]};
            await http.post(
              Uri.parse(url!),
              headers: headers,
              body: jsonEncode(body6),
            );
          }
        }
        var body5 = { "transaction": [
            {"query": "SELECT parking_name, file_address FROM tb_parking_zone" }
          ]};
        var parkingZone = await http.post(
          Uri.parse(url!),
          headers: headers,
          body: jsonEncode(body5),
        );
        var dcParkingZone = jsonDecode(parkingZone.body);
        var resultSet5 = dcParkingZone['results'][0]['resultSet'];
        // print(resultSet5);
        var body7 = { "transaction": [
            {"query": "SELECT * FROM tb_lot_type" }
          ]};
        var lotType = await http.post(
          Uri.parse(url),
          headers: headers,
          body: jsonEncode(body7),
        );
        var dcLotType = jsonDecode(utf8.decode(lotType.bodyBytes));
        var resultSet7 = dcLotType['results'][0]['resultSet'];
        print("resultSet7 : $resultSet7");
        // print("token : $listtoken");

        // print(resultSet7);
        return Response.ok(
            jsonEncode(check + resultSet1 + resultSet7 + resultSet4 + resultSet3 + resultSet5 + listtoken),
            headers: headers);
      } else if (loginCheck == 0) {
        print('아이디 틀렸습니다.');
        return Response.internalServerError(body: '아이디 혹은 비밀번호가 틀렸습니다.');
      } else if (loginCheck == 1) {
        print('비밀번호? 틀렸습니다.');
        return Response.internalServerError(body: '아이디 혹은 비밀번호가 틀렸습니다');
      }
    });
    router.get('/jwt', (Request request) async{
      return Response.ok(jsonEncode({'token': token}), headers: {
        'Content-Type': 'application/json',
      });
    });
    router.get('/protected', (Request request) async {
    final authorizationHeader = request.headers['Authorization'];
    if (authorizationHeader != null && authorizationHeader.startsWith('Bearer ')) {
      final token = authorizationHeader.substring('Bearer '.length);
      if (verifyJwt(token)) {
        return Response.ok('Access granted to protected resource.');
      } else {
        return Response.forbidden('Invalid token.');
      }
    } else {
      return Response.forbidden('Authorization header missing.');
    }
  });
    return router;
  }
  String createJwt(String username, int hours) {
    final jwt = JWT(
      {
        'account': username,
        'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
        'exp': DateTime.now().add(Duration(hours: hours)).millisecondsSinceEpoch ~/ 1000, // 만료 시간 추가
      },
    );
    return jwt.sign(SecretKey(_secretKey));
  }
  bool verifyJwt(String token) {
    try {
      final jwt = JWT.verify(token, SecretKey(_secretKey));
      return true; // 유효한 토큰
    } catch (e) {
      return false; // 유효하지 않은 토큰
    }
  }
  // 서버로 요청 보내는 함수
  //사진 크기 요청..?
  Future<http.Response> _ReqToWs4TotalPixel(var displayDbAddr) async {
    String url = displayDbAddr;
    Map<String, String> headers = {'Content-Type': 'application/json'};
    Map<String, dynamic> body = {
      "transaction": [
        {"query": "#S_TotalPixel"}
      ]
    };
    return await http.post(
      Uri.parse(url),
      headers: headers,
      body: jsonEncode(body),
    );
  }

  // 서버로 요청 보내는 함수
  // 좌표 요청
  Future<http.Response> _ReqToWs4LotInfo(var displayDbAddr) async {
    String url = displayDbAddr;
    Map<String, String> headers = {'Content-Type': 'application/json'};
    Map<String, dynamic> body = {
      "transaction": [
        {"query": "#S_LotInfo"}
      ]
    };
    return await http.post(
      Uri.parse(url),
      headers: headers,
      body: jsonEncode(body),
    );
  }

  // 서버로 요청 보내는 함수
  Future<http.Response> _ReqToWs4LotType(var displayDbAddr) async {
    String url = displayDbAddr;
    Map<String, String> headers = {'Content-Type': 'application/json'};
    Map<String, dynamic> body = {
      "transaction": [
        {"query": "#S_LotType"}
      ]
    };
    return await http.post(
      Uri.parse(url),
      headers: headers,
      body: jsonEncode(body),
    );
  }

  Future<http.Response> _ReqToWs4Login(
      var account, var passwd, var displayDbAddr) async {
    String url = displayDbAddr;
    Map<String, String> headers = {'Content-Type': 'application/json'};
    Map<String, dynamic> body = {
      "transaction": [
        {
          "query":
              "SELECT * FROM tb_users WHERE account = :account AND passwd = :passwd",
          "values": {"account": account, "passwd": passwd}
        }
      ]
    };
    return await http.post(
      Uri.parse(url),
      headers: headers,
      body: jsonEncode(body),
    );
  }
}
