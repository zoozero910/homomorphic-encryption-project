
#include <seal/seal.h>

#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>

using namespace std;
using namespace seal;

int main()
{
    // 1. BFV 암호화 파라미터 설정
    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 8192;

    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(
        CoeffModulus::BFVDefault(poly_modulus_degree)
    );

    parms.set_plain_modulus(
        PlainModulus::Batching(poly_modulus_degree, 20)
    );

    SEALContext context(parms);

    if (!context.parameters_set())
    {
        cerr << "암호화 파라미터가 올바르지 않습니다.\n";
        return 1;
    }

    // 2. 암호화 키 생성
    KeyGenerator keygen(context);

    SecretKey secret_key = keygen.secret_key();

    PublicKey public_key;
    keygen.create_public_key(public_key);

    // 3. 암호화에 필요한 도구 생성
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    size_t slot_count = batch_encoder.slot_count();

    // 4. 실험용 가상 사용자 데이터
    // 0 = 서울, 1 = 부산, 2 = 대구
    vector<int> user_regions = {0, 1, 0, 2, 1};

    vector<string> region_names = {
        "서울", "부산", "대구"
    };

    // 5. 사용자별 데이터 암호화
    vector<Ciphertext> encrypted_users;

    for (size_t i = 0; i < user_regions.size(); i++)
    {
        // 모든 슬롯을 0으로 초기화
        vector<uint64_t> region_vector(slot_count, 0);

        // 해당 지역의 슬롯만 1로 설정
        region_vector[user_regions[i]] = 1;

        // 벡터를 평문 다항식으로 변환
        Plaintext plain;
        batch_encoder.encode(region_vector, plain);

        // 평문을 암호화
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);

        encrypted_users.push_back(encrypted);

        cout << "사용자 " << i + 1
             << " 암호화 완료\n";
    }

    // 6. 암호문 상태에서 지역별 인원 합산
    Ciphertext encrypted_total = encrypted_users[0];

    for (size_t i = 1; i < encrypted_users.size(); i++)
    {
        evaluator.add_inplace(
            encrypted_total,
            encrypted_users[i]
        );
    }

    cout << "\n암호문 덧셈 완료\n";

    cout << "남은 노이즈 예산: "
         << decryptor.invariant_noise_budget(encrypted_total)
         << " bits\n";

    // 7. 최종 결과 복호화
    Plaintext decrypted_plain;

    decryptor.decrypt(
        encrypted_total,
        decrypted_plain
    );

    // 8. 평문 다항식을 다시 숫자 벡터로 변환
    vector<uint64_t> result;

    batch_encoder.decode(
        decrypted_plain,
        result
    );

    // 9. 결과 출력
    cout << "\n===== 지역별 인원 수 =====\n";

    for (size_t i = 0; i < region_names.size(); i++)
    {
        cout << region_names[i]
             << ": "
             << result[i]
             << "명\n";
    }

    // 10. 평문으로 계산한 정답과 비교
    vector<uint64_t> expected = {2, 2, 1};

    bool correct = true;

    for (size_t i = 0; i < expected.size(); i++)
    {
        if (result[i] != expected[i])
        {
            correct = false;
        }
    }

    
    cout << "\n통계 검증 결과: "
         << (correct ? "성공" : "실패")
         << "\n";

    // ==========================================
    // 11. 암호화된 사용자 데이터에서 지역 검색
    // ==========================================

    cout << "\n===== 지역 검색 =====\n";

    // 서울 = 0, 부산 = 1, 대구 = 2
    size_t search_region = 0;

    cout << "검색 지역: "
         << region_names[search_region] << "\n\n";

    // 서울을 선택하는 평문 검색 벡터
    vector<uint64_t> search_vector(slot_count, 0);

    search_vector[search_region] = 1;

    // 검색 벡터 인코딩
    Plaintext search_plain;

    batch_encoder.encode(
        search_vector,
        search_plain
    );

    // 사용자별 검색 결과
    uint64_t match_count = 0;
    bool search_correct = true;

    for (size_t i = 0; i < encrypted_users.size(); i++)
    {
        // 암호화된 사용자 데이터와
        // 평문 검색 조건을 슬롯별로 곱함
        Ciphertext encrypted_match;

        evaluator.multiply_plain(
            encrypted_users[i],
            search_plain,
            encrypted_match
        );

        // 검색 결과 복호화
        Plaintext decrypted_match;

        decryptor.decrypt(
            encrypted_match,
            decrypted_match
        );

        // 복호화된 결과를 벡터로 변환
        vector<uint64_t> match_vector;

        batch_encoder.decode(
            decrypted_match,
            match_vector
        );

        // 서울 검색이므로 0번 슬롯 확인
        uint64_t is_match =
            match_vector[search_region];

        match_count += is_match;

        cout << "사용자 " << i + 1 << ": "
             << (is_match == 1 ? "일치" : "불일치")
             << "\n";

        // 평문 데이터와 비교하여 검증
        uint64_t expected_match =
            (user_regions[i] == static_cast<int>(search_region))
            ? 1 : 0;

        if (is_match != expected_match)
        {
            search_correct = false;
        }
    }

    cout << "\n검색 결과: "
         << match_count << "명\n";

    // 검색 결과의 전체 인원도 검증
    if (match_count != expected[search_region])
    {
        search_correct = false;
    }

    cout << "검색 검증 결과: "
         << (search_correct ? "성공" : "실패")
         << "\n";

    // 통계와 검색이 모두 성공했는지 확인
    return (correct && search_correct) ? 0 : 1;
}

