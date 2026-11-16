
#include <seal/seal.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>
#include <iomanip>

using namespace std;
using namespace seal;

struct User
{
    int id;
    int region;
    int age_group;
    int purchase_amount;
};

vector<User> load_users(const string &filename)
{
    ifstream file(filename);

    if (!file.is_open())
        throw runtime_error("users.csv 파일을 열 수 없습니다.");

    vector<User> users;
    string line;

    getline(file, line);

    while (getline(file, line))
    {
        if (line.empty()) continue;

        stringstream ss(line);
        string value;
        User u;

        getline(ss, value, ',');
        u.id = stoi(value);

        getline(ss, value, ',');
        u.region = stoi(value);

        getline(ss, value, ',');
        u.age_group = stoi(value);

        getline(ss, value, ',');
        u.purchase_amount = stoi(value);

        users.push_back(u);
    }

    return users;
}

int main()
{
    try
    {
        // ==================================
        // 1. 검색 조건 설정
        // ==================================

        const int REGION_COUNT = 10;
        const int AGE_COUNT = 6;

        const vector<string> region_names = {
            "서울", "부산", "대구", "인천", "광주",
            "대전", "울산", "세종", "경기", "강원"
        };

        int search_region = 8; // 서울
        int search_age = 50;   // 20대

        int search_age_index = search_age / 10 - 1;

        if (search_region < 0 ||
            search_region >= REGION_COUNT ||
            search_age_index < 0 ||
            search_age_index >= AGE_COUNT ||
            search_age != (search_age_index + 1) * 10)
        {
            throw runtime_error("검색 조건 오류");
        }

        vector<User> users = load_users("users.csv");

        cout << "총 사용자 수: "
             << users.size() << "명\n";

        cout << "검색 조건: "
             << region_names[search_region] << ", "
             << search_age << "대\n";

        // ==================================
        // 2. BFV 암호화 설정
        // ==================================

        EncryptionParameters parms(scheme_type::bfv);

        size_t degree = 8192;

        parms.set_poly_modulus_degree(degree);

        parms.set_coeff_modulus(
            CoeffModulus::BFVDefault(degree)
        );

        parms.set_plain_modulus(
            PlainModulus::Batching(degree, 20)
        );

        SEALContext context(parms);

        if (!context.parameters_set())
            throw runtime_error("BFV 파라미터 오류");

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
                "사용자 수는 1명~4096명이어야 합니다."
            );
        }

        // ==================================
        // 3. SIMD 슬롯에 데이터 배치
        // ==================================

        vector<vector<uint64_t>> region_slots(
            REGION_COUNT,
            vector<uint64_t>(slot_count, 0)
        );

        vector<vector<uint64_t>> age_slots(
            AGE_COUNT,
            vector<uint64_t>(slot_count, 0)
        );

        vector<uint64_t> amount_slots(slot_count, 0);

        uint64_t maximum_sum = 0;

        for (size_t i = 0; i < users.size(); i++)
        {
            const User &u = users[i];

            int age_index = u.age_group / 10 - 1;

            if (u.region < 0 ||
                u.region >= REGION_COUNT ||
                age_index < 0 ||
                age_index >= AGE_COUNT ||
                u.age_group != (age_index + 1) * 10 ||
                u.purchase_amount < 0 ||
                u.purchase_amount % 1000 != 0)
            {
                throw runtime_error("잘못된 사용자 데이터");
            }

            // 핵심 ①: 사용자 i의 조건을 슬롯 i에 저장
            region_slots[u.region][i] = 1;
            age_slots[age_index][i] = 1;

            // 1000원 단위로 금액을 표현
            amount_slots[i] = u.purchase_amount / 1000;

            maximum_sum += amount_slots[i];
        }

        uint64_t t = parms.plain_modulus().value();

        if (maximum_sum >= t || users.size() >= t)
        {
            throw runtime_error(
                "합계가 평문 모듈러스 범위를 넘을 수 있습니다."
            );
        }

        // ==================================
        // 4. BFV 암호화
        // ==================================

        auto encrypt_slots = [&](const vector<uint64_t> &data)
        {
            Plaintext plain;
            Ciphertext encrypted;

            encoder.encode(data, plain);
            encryptor.encrypt(plain, encrypted);

            return encrypted;
        };

        vector<Ciphertext> encrypted_regions;
        vector<Ciphertext> encrypted_ages;

        for (int i = 0; i < REGION_COUNT; i++)
        {
            encrypted_regions.push_back(
                encrypt_slots(region_slots[i])
            );
        }

        for (int i = 0; i < AGE_COUNT; i++)
        {
            encrypted_ages.push_back(
                encrypt_slots(age_slots[i])
            );
        }

        Ciphertext encrypted_amount =
            encrypt_slots(amount_slots);

        cout << "\nSIMD 암호화 완료\n";
        cout << "암호문 개수: "
             << REGION_COUNT + AGE_COUNT + 1
             << "개\n";

        // ==================================
        // 5. 다중 조건 검색
        // ==================================

        cout << "\n초기 노이즈 예산: "
             << decryptor.invariant_noise_budget(
                 encrypted_regions[search_region]
             )
             << " bits\n";

        // 핵심 ②: 지역 여부 × 연령대 여부
        Ciphertext encrypted_match;

        evaluator.multiply(
            encrypted_regions[search_region],
            encrypted_ages[search_age_index],
            encrypted_match
        );

        evaluator.relinearize_inplace(
            encrypted_match,
            relin_keys
        );

        cout << "조건 곱셈 후 노이즈 예산: "
             << decryptor.invariant_noise_budget(
                 encrypted_match
             )
             << " bits\n";

        // 핵심 ③: 검색 결과 × 구매 금액
        Ciphertext encrypted_filtered_amount;

        evaluator.multiply(
            encrypted_match,
            encrypted_amount,
            encrypted_filtered_amount
        );

        evaluator.relinearize_inplace(
            encrypted_filtered_amount,
            relin_keys
        );

        cout << "금액 곱셈 후 노이즈 예산: "
             << decryptor.invariant_noise_budget(
                 encrypted_filtered_amount
             )
             << " bits\n";

        // ==================================
        // 6. SIMD 슬롯 합산
        // ==================================

        auto sum_slots = [&](Ciphertext encrypted)
        {
            for (size_t step = 1;
                 step < users.size();
                 step *= 2)
            {
                Ciphertext rotated;

                evaluator.rotate_rows(
                    encrypted,
                    static_cast<int>(step),
                    galois_keys,
                    rotated
                );

                evaluator.add_inplace(
                    encrypted,
                    rotated
                );
            }

            return encrypted;
        };

        // 핵심 ④: 암호문 상태에서 전체 합산
        Ciphertext encrypted_count =
            sum_slots(encrypted_match);

        Ciphertext encrypted_total_amount =
            sum_slots(encrypted_filtered_amount);

        cout << "최종 노이즈 예산: "
             << decryptor.invariant_noise_budget(
                 encrypted_total_amount
             )
             << " bits\n";

        // ==================================
        // 7. 최종 결과만 복호화
        // ==================================

        auto decrypt_first_slot = [&](const Ciphertext &encrypted)
        {
            Plaintext plain;
            vector<uint64_t> decoded;

            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, decoded);

            return decoded[0];
        };

        uint64_t encrypted_count_result =
            decrypt_first_slot(encrypted_count);

        uint64_t encrypted_amount_result =
            decrypt_first_slot(encrypted_total_amount) * 1000;

        // ==================================
        // 8. 평문 결과로 정확성 검증
        // ==================================

        uint64_t expected_count = 0;
        uint64_t expected_amount = 0;

        for (const User &u : users)
        {
            if (u.region == search_region &&
                u.age_group == search_age)
            {
                expected_count++;
                expected_amount += u.purchase_amount;
            }
        }

        bool correct =
            encrypted_count_result == expected_count &&
            encrypted_amount_result == expected_amount;

        cout << "\n===== 조건부 통계 결과 =====\n";

        cout << "동형암호 검색 인원: "
             << encrypted_count_result << "명\n";

        cout << "평문 검색 인원: "
             << expected_count << "명\n";

        cout << "동형암호 구매 합계: "
             << encrypted_amount_result << "원\n";

        cout << "평문 구매 합계: "
             << expected_amount << "원\n";

        // ==================================
        // 9. 평균 구매 금액
        // ==================================

        if (encrypted_count_result > 0)
        {
            double average =
                static_cast<double>(encrypted_amount_result)
                / encrypted_count_result;

            cout << fixed << setprecision(2);

            cout << "평균 구매 금액: "
                 << average << "원\n";
        }
        else
        {
            cout << "평균 구매 금액: 계산 불가 (0명)\n";
        }

        cout << "\n최종 검증: "
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
