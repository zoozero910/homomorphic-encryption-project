#include "seal/seal.h" //seal 라이브러리 헤더 파일 포함
#include <iostream> //입출력 라이브러리 포함

using namespace std;  
using namespace seal;

int main() {
    //프로그램 시작
    cout << "Start" << endl; 
    EncryptionParameters parms (scheme_type::bfv);   //암호화 매개변수 설정 (사용할 암호화 스킴은 BFV)
    size_t poly_modulus_degree = 4096;                       //다항식 차수 설정 (다항식 차수는 4096로 설정, 차수는 암호화된 데이터의 크기와 보안 수준을 결정하는 값)
   
    //암호화 매개변수 설정 (매개변수에 다항식 차수, 계수 모듈러스, 평문 모듈러스 설정)
    parms.set_poly_modulus_degree(poly_modulus_degree);                                 //매개변수에 poly_modulus_degree 설정
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));             //계수 모듈러스는 암호화된 데이터의 크기와 보안 수준을 결정하는 값 설정
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));  //평문 모듈러스는 배칭 조건에 맞는 20비트 소수로 설정

  
    //SEAL 컨텍스트 생성(컨텍스트 내용은 암호화 매개변수와 관련된 내용 모두 포함: 암호화 매개변수, 키 생성기, 암호화기, 복호화기, 연산기 등)
    SEALContext context(parms);

    // 컨텍스트 사용하여 키 생성기, 암호화기, 복호화기, 연산기 생성 및 초기화
    KeyGenerator keygen(context);                           // 키 생성기 생성(컨텍스트를 사용하여 키 생성기 생성, 비밀키와 공개키를 생성하는 데 사용
    SecretKey secret_key = keygen.secret_key();             // 비밀키 생성(KeyGenerator를 사용, 비밀키는 암호화된 데이터를 복호화하는 데 사용됨)
    PublicKey public_key;                                   // 공개키 생성(공캐키로 공개키를 생성하기 위해 PublicKey 객체 생성)               
    keygen.create_public_key(public_key);     // 공개키 생성(KeyGenerator를 사용, 공개키는 암호화된 데이터를 암호화하는 데 사용됨, 공개키는 비밀키와 쌍)
    Encryptor encryptor(context, public_key);               // 암호화기 생성(암호화로 사용되는 Encryptor 객체 생성)
    Evaluator evaluator(context);                           // 평문 연산기 생성(암호화된 데이터를 연산하는 데 사용)
    Decryptor decryptor(context, secret_key);               // 복호화기 생성(암호화된 데이터를 복호화하는 데 사용, SEALContext와 비밀키를 사용하여 초기화됨)
    
    // 암호화, 연산, 복호화 준비 완료
    cout << "Enc/Eval/Dec prepared!" << endl;               

    BatchEncoder encoder(context);                          //배치 인코더 생성(배열을 평문으로 인코딩하고, 평문을 배열로 디코딩하는 데 사용)
    size_t slot_count = encoder.slot_count();               //배치 인코더의 슬롯 수 가져오기(슬롯 수는 배치 인코더가 한 번에 처리할 수 있는 배열의 크기, slot_count는 poly_modulus_degree / 2와 같음)
    vector<uint64_t> plain_vector(slot_count, 0ULL);   //배열 생성 및 초기화(배열의 크기는 slot_count, 모든 요소를 0으로 초기화)
    plain_vector[0] = 2;                                    //배열의 첫 번째 요소를 2으로 설정
    plain_vector[1] = 7;                                    //배열의 두 번째 요소를 7로 설정
    
    //입력값 출력(배열의 첫 번째, 두 번째, 세 번째 요소를 출력)
    cout << "Input: " << plain_vector[0] << ", " << plain_vector[1] << ", " << plain_vector[2] << endl; 

    //평문 생성
    Plaintext plain;                                              //평문 객체 생성
    encoder.encode(plain_vector, plain);     //배치 인코더를 사용하여 배열을 평문으로 인코딩
    cout << "Plaintext created!" << endl;                         //평문 생성 완료

    //암호화 수행
    Ciphertext encrypted;                                          //암호문 객체 생성
    encryptor.encrypt(plain, encrypted);             //평문을 암호화하여 암호문 생성
    cout << "Enc completed!" << endl;                              //암호화 완료

    //암호문 연산 수행
    Ciphertext encrypted2 = encrypted;                             //암호문 복사
    evaluator.add_inplace(encrypted, encrypted2);      //더하기 연산 수행(암호문에 암호문을 더하여 암호문을 업데이트)
    evaluator.multiply_inplace(encrypted, encrypted2); //곱하기 연산 수행(암호문에 암호문을 곱하여 암호문을 업데이트)
    cout << "Ciphertext computation completed!" << endl;           //암호문 연산 완료

    //복호화 수행
    Plaintext plain_result;                                          //평문 결과 생성
    decryptor.decrypt(encrypted, plain_result);        //암호문을 복호화하여 평문 결과 생성
    vector<uint64_t> result_vector;                                  //결과를 저장할 배열 생성
    encoder.decode(plain_result, result_vector); //평문 결과를 배열로 디코딩
    
    //결과 출력
    cout << "End!" << endl;
    cout << "Result: (input+input)*input: " << result_vector[0] <<", " << result_vector[1] << ", " << result_vector[2] << endl;


    return 0; 
}


