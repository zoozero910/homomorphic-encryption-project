
#include <seal/seal.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <array>
#include <string>
#include <chrono>
#include <iomanip>
#include <stdexcept>
#include <cstdint>

using namespace std;
using namespace seal;

using Clock = chrono::steady_clock;

constexpr int REGION_COUNT = 10;
constexpr int AGE_COUNT = 6;

struct User
{
    int id;
    int region;
    int age_group;
    int purchase_amount;
};

struct Result
{
    Ciphertext count;
    Ciphertext amount;
};

struct MeasuredResult
{
    Result encrypted;
    double encryption_ms = 0;
    double calculation_ms = 0;
};

// CSV 파일 읽기
vector<User> load_users(const string &filename)
{
    ifstream file(filename);

    if (!file.is_open())
    {
        throw runtime_error("CSV 파일을 열 수 없습니다: " + filename);
    }

    vector<User> users;
    string line;

    getline(file, line); // 첫 줄은 제목

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

double milliseconds(Clock::time_point start)
{
    return chrono::duration<double, milli>(
        Clock::now() - start
    ).count();
}

int main()
{
    try
    {
        // ====================================
        // 1. 실험 설정
        // ====================================

        const int search_region = 0; // 서울
        const int search_age = 20;   // 20대

        const int search_age_index =
            search_age / 10 - 1;

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

        cout << "검색 조건: 서울, 20대\n";

        // ====================================
        // 2. Microsoft SEAL 설정
        // ====================================

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
        {
            throw runtime_error("BFV 파라미터 오류");
        }

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
                "현재 구현은 사용자 1~4096명만 지원합니다."
            );
        }

        // ====================================
        // 3. 입력 데이터 및 금액 범위 검증
        // ====================================

        uint64_t maximum_sum = 0;

        for (const User &user : users)
        {
            bool valid_region =
                user.region >= 0 &&
                user.region < REGION_COUNT;

            bool valid_age =
                user.age_group >= 10 &&
                user.age_group <= 60 &&
                user.age_group % 10 == 0;

            bool valid_amount =
                user.purchase_amount >= 0 &&
                user.purchase_amount % 1000 == 0;

            if (!valid_region ||
                !valid_age ||
                !valid_amount)
            {
                throw runtime_error(
                    "잘못된 CSV 사용자 데이터"
                );
            }

            maximum_sum +=
                static_cast<uint64_t>(
                    user.purchase_amount / 1000
                );
        }

        uint64_t plain_modulus =
            parms.plain_modulus().value();

        if (maximum_sum >= plain_modulus ||
            users.size() >= plain_modulus)
        {
            throw runtime_error(
                "합계가 평문 모듈러스 범위를 넘을 수 있습니다."
            );
        }

        // ====================================
        // 4. 공통 암호화 함수
        // ====================================

        auto encrypt_vector =
            [&](const vector<uint64_t> &values)
        {
            Plaintext plain;
            Ciphertext encrypted;

            encoder.encode(values, plain);
            encryptor.encrypt(plain, encrypted);

            return encrypted;
        };

        // ====================================
        // 5. 사용자별 방식: 메모리 절약형
        // ====================================

        cout << "\n[1] 사용자별 방식 계산 시작\n";

        MeasuredResult individual;
        bool first_user = true;

        for (const User &user : users)
        {
            // 사용자 한 명의 암호문만 생성
            array<Ciphertext, REGION_COUNT> encrypted_regions;
            array<Ciphertext, AGE_COUNT> encrypted_ages;

            Ciphertext encrypted_amount;

            auto start = Clock::now();

            // 지역 10종 암호화
            for (int j = 0; j < REGION_COUNT; j++)
            {
                vector<uint64_t> values(slot_count, 0);

                values[0] = (user.region == j) ? 1 : 0;

                encrypted_regions[j] =
                    encrypt_vector(values);
            }

            // 연령대 6종 암호화
            int user_age_index =
                user.age_group / 10 - 1;

            for (int j = 0; j < AGE_COUNT; j++)
            {
                vector<uint64_t> values(slot_count, 0);

                values[0] =
                    (user_age_index == j) ? 1 : 0;

                encrypted_ages[j] =
                    encrypt_vector(values);
            }

            // 구매 금액 암호화
            vector<uint64_t> amount_values(
                slot_count, 0
            );

            amount_values[0] =
                user.purchase_amount / 1000;

            encrypted_amount =
                encrypt_vector(amount_values);

            individual.encryption_ms +=
                milliseconds(start);

            // 핵심 ①: 암호문 상태에서 다중 조건 계산
            start = Clock::now();

            Ciphertext encrypted_match;

            evaluator.multiply(
                encrypted_regions[search_region],
                encrypted_ages[search_age_index],
                encrypted_match
            );

            evaluator.relinearize_inplace(
                encrypted_match, relin_keys
            );

            // 핵심 ②: 조건에 맞는 구매 금액 계산
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

            // 핵심 ③: 최종 암호문에 누적
            if (first_user)
            {
                individual.encrypted.count =
                    std::move(encrypted_match);

                individual.encrypted.amount =
                    std::move(encrypted_filtered_amount);

                first_user = false;
            }
            else
            {
                evaluator.add_inplace(
                    individual.encrypted.count,
                    encrypted_match
                );

                evaluator.add_inplace(
                    individual.encrypted.amount,
                    encrypted_filtered_amount
                );
            }

            individual.calculation_ms +=
                milliseconds(start);

            // 반복문 종료 시 사용자 한 명의
            // 임시 암호문은 더 이상 보관하지 않음
        }

        cout << "사용자별 방식 계산 완료\n";

        // ====================================
        // 6. SIMD 슬롯 데이터 준비
        // ====================================

        cout << "\n[2] SIMD 방식 계산 시작\n";

        MeasuredResult simd;

        auto simd_start = Clock::now();

        vector<vector<uint64_t>> region_slots(
            REGION_COUNT,
            vector<uint64_t>(slot_count, 0)
        );

        vector<vector<uint64_t>> age_slots(
            AGE_COUNT,
            vector<uint64_t>(slot_count, 0)
        );

        vector<uint64_t> amount_slots(
            slot_count, 0
        );

        for (size_t i = 0; i < users.size(); i++)
        {
            const User &user = users[i];

            region_slots[user.region][i] = 1;

            int age_index =
                user.age_group / 10 - 1;

            age_slots[age_index][i] = 1;

            amount_slots[i] =
                user.purchase_amount / 1000;
        }

        vector<Ciphertext> simd_regions(
            REGION_COUNT
        );

        vector<Ciphertext> simd_ages(
            AGE_COUNT
        );

        Ciphertext simd_amount;

        // 지역 10종 암호화
        for (int j = 0; j < REGION_COUNT; j++)
        {
            simd_regions[j] =
                encrypt_vector(region_slots[j]);
        }

        // 연령대 6종 암호화
        for (int j = 0; j < AGE_COUNT; j++)
        {
            simd_ages[j] =
                encrypt_vector(age_slots[j]);
        }

        // 구매 금액 암호화
        simd_amount =
            encrypt_vector(amount_slots);

        simd.encryption_ms =
            milliseconds(simd_start);

        // ====================================
        // 7. SIMD 암호문 조건부 통계
        // ====================================

        simd_start = Clock::now();

        Ciphertext simd_match;

        evaluator.multiply(
            simd_regions[search_region],
            simd_ages[search_age_index],
            simd_match
        );

        evaluator.relinearize_inplace(
            simd_match, relin_keys
        );

        Ciphertext simd_filtered_amount;

        evaluator.multiply(
            simd_match,
            simd_amount,
            simd_filtered_amount
        );

        evaluator.relinearize_inplace(
            simd_filtered_amount,
            relin_keys
        );

        // SIMD 슬롯 회전 + 합산
        auto sum_slots =
            [&](Ciphertext encrypted)
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
                    encrypted, rotated
                );
            }

            return encrypted;
        };

        simd.encrypted.count =
            sum_slots(simd_match);

        simd.encrypted.amount =
            sum_slots(simd_filtered_amount);

        simd.calculation_ms =
            milliseconds(simd_start);

        cout << "SIMD 방식 계산 완료\n";

        // ====================================
        // 8. 복호화 및 시간 측정
        // ====================================

        auto decrypt_result =
            [&](const Result &result)
        {
            Plaintext count_plain;
            Plaintext amount_plain;

            decryptor.decrypt(
                result.count, count_plain
            );

            decryptor.decrypt(
                result.amount, amount_plain
            );

            vector<uint64_t> counts;
            vector<uint64_t> amounts;

            encoder.decode(count_plain, counts);
            encoder.decode(amount_plain, amounts);

            return array<uint64_t, 2>{
                counts[0],
                amounts[0] * 1000
            };
        };

        auto start = Clock::now();

        auto individual_values =
            decrypt_result(individual.encrypted);

        double individual_decrypt_ms =
            milliseconds(start);

        start = Clock::now();

        auto simd_values =
            decrypt_result(simd.encrypted);

        double simd_decrypt_ms =
            milliseconds(start);

        // ====================================
        // 9. 평문 정답 검증
        // ====================================

        uint64_t expected_count = 0;
        uint64_t expected_amount = 0;

        for (const User &user : users)
        {
            if (user.region == search_region &&
                user.age_group == search_age)
            {
                expected_count++;
                expected_amount +=
                    user.purchase_amount;
            }
        }

        bool correct =
            individual_values[0] == expected_count &&
            individual_values[1] == expected_amount &&
            simd_values[0] == expected_count &&
            simd_values[1] == expected_amount;

        // ====================================
        // 10. 실험 결과 출력
        // ====================================

        cout << fixed << setprecision(3);

        cout << "\n===== 정확성 검증 =====\n";

        cout << "평문 인원: "
             << expected_count << "명\n";

        cout << "평문 구매 합계: "
             << expected_amount << "원\n";

        cout << "사용자별 방식: "
             << individual_values[0] << "명, "
             << individual_values[1] << "원\n";

        cout << "SIMD 방식: "
             << simd_values[0] << "명, "
             << simd_values[1] << "원\n";

        if (simd_values[0] > 0)
        {
            double average =
                static_cast<double>(simd_values[1]) /
                simd_values[0];

            cout << "평균 구매액: "
                 << average << "원\n";
        }
        else
        {
            cout << "평균 구매액: 계산 불가 (0명)\n";
        }

        cout << "\n===== 성능 비교 (ms) =====\n";

        cout << "암호화 및 인코딩 시간\n";

        cout << "  사용자별: "
             << individual.encryption_ms << "\n";

        cout << "  SIMD: "
             << simd.encryption_ms << "\n";

        cout << "검색 및 통계 계산 시간\n";

        cout << "  사용자별: "
             << individual.calculation_ms << "\n";

        cout << "  SIMD: "
             << simd.calculation_ms << "\n";

        cout << "복호화 및 디코딩 시간\n";

        cout << "  사용자별: "
             << individual_decrypt_ms << "\n";

        cout << "  SIMD: "
             << simd_decrypt_ms << "\n";

        cout << "\n===== 노이즈 예산 =====\n";

        cout << "사용자별: "
             << decryptor.invariant_noise_budget(
                 individual.encrypted.amount
             )
             << " bits\n";

        cout << "SIMD: "
             << decryptor.invariant_noise_budget(
                 simd.encrypted.amount
             )
             << " bits\n";

        cout << "\n===== 암호문 개수 =====\n";

        int ciphertexts_per_user =
            REGION_COUNT + AGE_COUNT + 1;

        cout << "사용자별 생성 총수: "
             << users.size() * ciphertexts_per_user
             << "개\n";

        cout << "SIMD 생성 총수: "
             << ciphertexts_per_user
             << "개\n";

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
