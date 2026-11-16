
#include <seal/seal.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <array>
#include <stdexcept>
#include <cstdint>

using namespace std;
using namespace seal;

// 가상 사용자 한 명의 정보
struct User
{
    int id;
    int region;
    int age_group;
    int purchase_amount;
};

// CSV 파일 읽기
vector<User> load_users(const string &filename)
{
    ifstream file(filename);

    if (!file.is_open())
    {
        throw runtime_error("CSV 파일을 열 수 없습니다.");
    }

    vector<User> users;
    string line;

    getline(file, line); // 제목 건너뛰기

    while (getline(file, line))
    {
        if (line.empty()) continue;

        stringstream ss(line);
        string value;
        User user;

        getline(ss, value, ',');
        user.id = stoi(value);

        getline(ss, value, ',');
        user.region = stoi(value);

        getline(ss, value, ',');
        user.age_group = stoi(value);

        getline(ss, value, ',');
        user.purchase_amount = stoi(value);

        users.push_back(user);
    }

    return users;
}

int main()
{
    try
    {
        // 1. 데이터 읽기
        vector<User> users = load_users("users.csv");

        cout << "총 사용자 수: "
             << users.size() << "명\n";

        // 2. 검색 조건
        int search_region = 0; // 서울
        int search_age = 20;   // 20대

        string region_names[] = {
            "서울", "부산", "대구"
        };

        int age_index = search_age / 10 - 2;

        if (search_region < 0 || search_region > 2 ||
            age_index < 0 || age_index > 2)
        {
            throw runtime_error("검색 조건이 올바르지 않습니다.");
        }

        // 3. BFV 설정
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
            throw runtime_error("BFV 파라미터 오류");
        }

        // 4. 암호화 키 생성
        KeyGenerator keygen(context);

        SecretKey secret_key = keygen.secret_key();

        PublicKey public_key;
        keygen.create_public_key(public_key);

        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);

        GaloisKeys galois_keys;
        keygen.create_galois_keys(galois_keys);

        Encryptor encryptor(context, public_key);
        Evaluator evaluator(context);
        Decryptor decryptor(context, secret_key);
        BatchEncoder encoder(context);

        size_t slot_count = encoder.slot_count();
        size_t row_size = slot_count / 2;

        if (users.empty() || users.size() > row_size)
        {
            throw runtime_error(
                "사용자 수가 SIMD 첫 번째 행의 범위를 벗어났습니다."
            );
        }

        // 5. SIMD 데이터 벡터 준비
        array<vector<uint64_t>, 3> region_slots;
        array<vector<uint64_t>, 3> age_slots;

        for (int i = 0; i < 3; i++)
        {
            region_slots[i].assign(slot_count, 0);
            age_slots[i].assign(slot_count, 0);
        }

        vector<uint64_t> amount_slots(slot_count, 0);

        // 핵심 ①: 사용자 100명을 슬롯에 배치
        for (size_t i = 0; i < users.size(); i++)
        {
            const User &user = users[i];

            int user_age_index = user.age_group / 10 - 2;

            if (user.region < 0 || user.region > 2 ||
                user_age_index < 0 || user_age_index > 2 ||
                user.age_group != (user_age_index + 2) * 10)
            {
                throw runtime_error("잘못된 사용자 데이터");
            }

            if (user.purchase_amount < 0 ||
                user.purchase_amount % 1000 != 0)
            {
                throw runtime_error(
                    "구매 금액은 1000원 단위여야 합니다."
                );
            }

            region_slots[user.region][i] = 1;
            age_slots[user_age_index][i] = 1;

            // 구매 금액: 1000원 단위로 저장
            amount_slots[i] = user.purchase_amount / 1000;
        }

        // 금액 합계가 BFV 평문 범위를 넘지 않는지 확인
        uint64_t maximum_sum = 0;

        for (const User &user : users)
        {
            maximum_sum += user.purchase_amount / 1000;
        }

        uint64_t plain_modulus = parms.plain_modulus().value();

        if (maximum_sum >= plain_modulus ||
            users.size() >= plain_modulus)
        {
            throw runtime_error(
                "합계가 평문 모듈러스 범위를 넘을 수 있습니다."
            );
        }

        // 6. 인코딩 및 암호화 함수
        auto encrypt_slots = [&](const vector<uint64_t> &slots)
        {
            Plaintext plain;
            Ciphertext encrypted;

            encoder.encode(slots, plain);
            encryptor.encrypt(plain, encrypted);

            return encrypted;
        };

        // 7. 지역 3개, 연령대 3개, 구매 금액 1개 암호화
        vector<Ciphertext> encrypted_regions;
        vector<Ciphertext> encrypted_ages;

        for (int i = 0; i < 3; i++)
        {
            encrypted_regions.push_back(
                encrypt_slots(region_slots[i])
            );

            encrypted_ages.push_back(
                encrypt_slots(age_slots[i])
            );
        }

        Ciphertext encrypted_amount =
            encrypt_slots(amount_slots);

        cout << "\nSIMD 암호화 완료\n";
        cout << "암호문 개수: 7개\n";

        cout << "검색 조건: "
             << region_names[search_region]
             << ", " << search_age << "대\n";

        cout << "초기 노이즈 예산: "
             << decryptor.invariant_noise_budget(
                 encrypted_regions[search_region]
             )
             << " bits\n";

        // 핵심 ②: 지역 조건 × 연령대 조건
        Ciphertext encrypted_match;

        evaluator.multiply(
            encrypted_regions[search_region],
            encrypted_ages[age_index],
            encrypted_match
        );

        evaluator.relinearize_inplace(
            encrypted_match, relin_keys
        );

        cout << "조건 곱셈 후 노이즈 예산: "
             << decryptor.invariant_noise_budget(
                 encrypted_match
             )
             << " bits\n";

        // 핵심 ③: 조건 만족 여부 × 구매 금액
        Ciphertext encrypted_purchase_sum;

        evaluator.multiply(
            encrypted_match,
            encrypted_amount,
            encrypted_purchase_sum
        );

        evaluator.relinearize_inplace(
            encrypted_purchase_sum, relin_keys
        );

        cout << "금액 곱셈 후 노이즈 예산: "
             << decryptor.invariant_noise_budget(
                 encrypted_purchase_sum
             )
             << " bits\n";

        // 핵심 ④: Rotation으로 슬롯 합산
        // 사용자 수를 포함하는 2의 거듭제곱만큼 합산
        auto sum_slots = [&](Ciphertext encrypted)
        {
            for (size_t step = 1; step < users.size(); step *= 2)
            {
                Ciphertext rotated;

                evaluator.rotate_rows(
                    encrypted,
                    static_cast<int>(step),
                    galois_keys,
                    rotated
                );

                evaluator.add_inplace(
                    encrypted, rotated
                );
            }

            return encrypted;
        };

        Ciphertext encrypted_count =
            sum_slots(encrypted_match);

        Ciphertext encrypted_total_amount =
            sum_slots(encrypted_purchase_sum);

        cout << "최종 금액 암호문 노이즈 예산: "
             << decryptor.invariant_noise_budget(
                 encrypted_total_amount
             )
             << " bits\n";

        // 8. 최종 결과만 복호화
        auto decrypt_first_slot = [&](const Ciphertext &encrypted)
        {
            Plaintext plain;
            vector<uint64_t> result;

            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, result);

            return result[0];
        };

        uint64_t encrypted_count_result =
            decrypt_first_slot(encrypted_count);

        uint64_t encrypted_amount_result =
            decrypt_first_slot(encrypted_total_amount) * 1000;

        // 9. 평문 계산으로 정답 검증
        uint64_t expected_count = 0;
        uint64_t expected_amount = 0;

        for (const User &user : users)
        {
            if (user.region == search_region &&
                user.age_group == search_age)
            {
                expected_count++;
                expected_amount += user.purchase_amount;
            }
        }

        cout << "\n===== 조건부 통계 결과 =====\n";

        cout << "동형암호 검색 인원: "
             << encrypted_count_result << "명\n";

        cout << "평문 검색 인원: "
             << expected_count << "명\n";

        cout << "동형암호 구매 합계: "
             << encrypted_amount_result << "원\n";

        cout << "평문 구매 합계: "
             << expected_amount << "원\n";

        bool correct =
            encrypted_count_result == expected_count &&
            encrypted_amount_result == expected_amount;

        cout << "\n검증 결과: "
             << (correct ? "성공" : "실패")
             << "\n";

        return correct ? 0 : 1;
    }
    catch (const exception &e)
    {
        cerr << "오류: " << e.what() << "\n";
        return 1;
    }
}
