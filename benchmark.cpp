
#include <seal/seal.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <array>
#include <string>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <stdexcept>
#include <cstdint>

using namespace std;
using namespace seal;

using Clock = chrono::steady_clock;

struct User
{
    int id;
    int region;
    int age_group;
    int purchase_amount;
};

// 사용자 1명의 암호문 7개
struct EncryptedUser
{
    array<Ciphertext, 10> regions;
    array<Ciphertext, 6> ages;
    Ciphertext amount;
};

struct Result
{
    Ciphertext count;
    Ciphertext amount;
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

double elapsed_ms(Clock::time_point start)
{
    return chrono::duration<double, milli>(
        Clock::now() - start
    ).count();
}

double median(vector<double> values)
{
    sort(values.begin(), values.end());
    return values[values.size() / 2];
}

int main()
{
    try
    {
        vector<User> users = load_users("users.csv");

        // ===== 실험 설정 =====
    const int REGION_COUNT = 10;
    const int AGE_COUNT = 6;

    const int search_region = 0; // 서울
    const int search_age = 20;   // 20대
    const int repeat_count = 3;

    const int search_age_index = search_age / 10 - 1;

        if (search_region < 0 ||
        search_region >= REGION_COUNT ||
        search_age_index < 0 ||
        search_age_index >= AGE_COUNT ||
        search_age != (search_age_index + 1) * 10)
    {
        throw runtime_error("검색 조건 오류");
    }
        cout << "총 사용자 수: " << users.size() << "명\n";
        cout << "검색 조건: 지역 " << search_region
             << ", 연령대 " << search_age << "대\n\n";

        // ===== SEAL 설정 =====
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
            throw runtime_error("SEAL 파라미터 오류");

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
            throw runtime_error("사용자 수가 SIMD 한 행 범위를 초과");
        
        // 입력 데이터 확인 및 합계 범위 검증
        uint64_t maximum_sum = 0;

        for (const User &u : users)
        {
            // 지역은 0~9
            bool valid_region =
                u.region >= 0 &&
                u.region < REGION_COUNT;

            // 연령대는 10,20,30,40,50,60
            bool valid_age =
                u.age_group >= 10 &&
                u.age_group <= 60 &&
                u.age_group % 10 == 0;

            // 구매 금액은 0 이상, 1000원 단위
            bool valid_amount =
                u.purchase_amount >= 0 &&
                u.purchase_amount % 1000 == 0;

            if (!valid_region ||
                !valid_age ||
                !valid_amount)
            {
                throw runtime_error("잘못된 CSV 데이터");
            }

            maximum_sum +=
                static_cast<uint64_t>(
                    u.purchase_amount / 1000
                );
        }

        uint64_t t = parms.plain_modulus().value();

        if (maximum_sum >= t ||
            users.size() >= t)
        {
            throw runtime_error(
                "평문 모듈러스 범위 초과"
            );
        }


        // 공통 암호화 함수
        auto encrypt_vector = [&](const vector<uint64_t> &data)
        {
            Plaintext plain;
            Ciphertext encrypted;

            encoder.encode(data, plain);
            encryptor.encrypt(plain, encrypted);

            return encrypted;
        };

        // ===========================================
        // 방식 A: 사용자별 암호화
        // ===========================================

        vector<EncryptedUser> individual;
        individual.reserve(users.size());

        auto start = Clock::now();

        for (const User &u : users)
        {
            EncryptedUser enc;

            
            int age_index = u.age_group / 10 - 1;

            // 지역 암호문 10개 생성
            for (int j = 0; j < REGION_COUNT; j++)
            {
                vector<uint64_t> region_data(slot_count, 0);

                region_data[0] = (u.region == j) ? 1 : 0;

                enc.regions[j] = encrypt_vector(region_data);
            }

            // 연령대 암호문 6개 생성
            for (int j = 0; j < AGE_COUNT; j++)
            {
                vector<uint64_t> age_data(slot_count, 0);

                age_data[0] = (age_index == j) ? 1 : 0;

                enc.ages[j] = encrypt_vector(age_data);
            }


            vector<uint64_t> amount_data(slot_count, 0);
            amount_data[0] = u.purchase_amount / 1000;

            enc.amount = encrypt_vector(amount_data);

            individual.push_back(std::move(enc));
        }

        double individual_encrypt_ms = elapsed_ms(start);

        // ===========================================
        // 방식 B: SIMD 배치 암호화
        // ===========================================

        vector<vector<uint64_t>> region_slots(
            REGION_COUNT,
            vector<uint64_t>(slot_count, 0)
        );

        vector<vector<uint64_t>> age_slots(
            AGE_COUNT,
            vector<uint64_t>(slot_count, 0)
        );

        vector<uint64_t> amount_slots(slot_count, 0);

        for (size_t i = 0; i < users.size(); i++)
        {
            const User &u = users[i];

            region_slots[u.region][i] = 1;
            age_slots[u.age_group / 10 - 1][i] = 1;
            amount_slots[i] = u.purchase_amount / 1000;
        }

        
        vector<Ciphertext> simd_regions(REGION_COUNT);
        vector<Ciphertext> simd_ages(AGE_COUNT);

        Ciphertext simd_amount;

        start = Clock::now();

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
        simd_amount = encrypt_vector(amount_slots);

        double simd_encrypt_ms = elapsed_ms(start);


        // ===========================================
        // 핵심 ①: 사용자별 방식의 검색 및 통계
        // ===========================================

        auto calculate_individual = [&]()
        {
            Result result;
            bool first = true;

            for (const EncryptedUser &u : individual)
            {
                Ciphertext match;

                evaluator.multiply(
                    u.regions[search_region],
                    u.ages[search_age_index],
                    match
                );

                evaluator.relinearize_inplace(
                    match, relin_keys
                );

                Ciphertext amount;

                evaluator.multiply(
                    match,
                    u.amount,
                    amount
                );

                evaluator.relinearize_inplace(
                    amount, relin_keys
                );

                if (first)
                {
                    result.count = match;
                    result.amount = amount;
                    first = false;
                }
                else
                {
                    evaluator.add_inplace(result.count, match);
                    evaluator.add_inplace(result.amount, amount);
                }
            }

            return result;
        };

        // ===========================================
        // 핵심 ②: SIMD 방식의 검색 및 통계
        // ===========================================

        auto calculate_simd = [&]()
        {
            Result result;

            evaluator.multiply(
                simd_regions[search_region],
                simd_ages[search_age_index],
                result.count
            );

            evaluator.relinearize_inplace(
                result.count, relin_keys
            );

            evaluator.multiply(
                result.count,
                simd_amount,
                result.amount
            );

            evaluator.relinearize_inplace(
                result.amount, relin_keys
            );

            // SIMD 슬롯 합산
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
                        encrypted, rotated
                    );
                }

                return encrypted;
            };

            result.count = sum_slots(result.count);
            result.amount = sum_slots(result.amount);

            return result;
        };

        // ===========================================
        // 계산 시간 측정
        // ===========================================

        vector<double> individual_times;
        vector<double> simd_times;

        Result individual_result;
        Result simd_result;

        // 사전 실행: 최초 호출 효과 일부 완화
        individual_result = calculate_individual();
        simd_result = calculate_simd();

        for (int i = 0; i < repeat_count; i++)
        {
            start = Clock::now();

            individual_result = calculate_individual();

            individual_times.push_back(elapsed_ms(start));

            start = Clock::now();

            simd_result = calculate_simd();

            simd_times.push_back(elapsed_ms(start));
        }

        double individual_calc_ms = median(individual_times);
        double simd_calc_ms = median(simd_times);

        // ===========================================
        // 복호화 시간 측정
        // ===========================================

        auto decrypt_result = [&](const Result &result)
        {
            Plaintext count_plain;
            Plaintext amount_plain;

            vector<uint64_t> counts;
            vector<uint64_t> amounts;

            decryptor.decrypt(result.count, count_plain);
            decryptor.decrypt(result.amount, amount_plain);

            encoder.decode(count_plain, counts);
            encoder.decode(amount_plain, amounts);

            return array<uint64_t, 2>{
                counts[0],
                amounts[0] * 1000
            };
        };

        start = Clock::now();
        auto individual_values = decrypt_result(individual_result);
        double individual_decrypt_ms = elapsed_ms(start);

        start = Clock::now();
        auto simd_values = decrypt_result(simd_result);
        double simd_decrypt_ms = elapsed_ms(start);

        // 평문 결과 계산
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
            individual_values[0] == expected_count &&
            individual_values[1] == expected_amount &&
            simd_values[0] == expected_count &&
            simd_values[1] == expected_amount;

        
        // ===========================================
        // 결과 출력
        // ===========================================

        // 조건을 만족하는 사람이 없으면 평균을 구할 수 없음
        if (simd_values[0] > 0)
        {
            double average =
                static_cast<double>(simd_values[1]) /
                simd_values[0];

            cout << "\n===== 평균 구매 금액 =====\n";
            cout << "평균 구매 금액: "
                 << average << "원\n";
        }
        else
        {
            cout << "\n조건을 만족하는 사용자가 없어 "
                 << "평균을 계산할 수 없습니다.\n";
        }

        cout << fixed << setprecision(3);

        cout << "\n===== 정확성 검증 =====\n";
        cout << "평문 인원: " << expected_count << "명\n";
        cout << "평문 구매 합계: " << expected_amount << "원\n\n";

        cout << "사용자별 방식: "
             << individual_values[0] << "명, "
             << individual_values[1] << "원\n";

        cout << "SIMD 방식: "
             << simd_values[0] << "명, "
             << simd_values[1] << "원\n";

        cout << "\n===== 성능 비교 (ms) =====\n";
        cout << "암호화 시간\n";
        cout << "  사용자별: " << individual_encrypt_ms << "\n";
        cout << "  SIMD:     " << simd_encrypt_ms << "\n";

        cout << "검색 + 통계 계산 시간 (3회 중앙값)\n";
        cout << "  사용자별: " << individual_calc_ms << "\n";
        cout << "  SIMD:     " << simd_calc_ms << "\n";

        cout << "복호화 + 디코딩 시간 (1회)\n";
        cout << "  사용자별: " << individual_decrypt_ms << "\n";
        cout << "  SIMD:     " << simd_decrypt_ms << "\n";

        cout << "\n===== 노이즈 예산 =====\n";
        cout << "사용자별 방식: "
             << decryptor.invariant_noise_budget(
                 individual_result.amount
             ) << " bits\n";

        cout << "SIMD 방식: "
             << decryptor.invariant_noise_budget(
                 simd_result.amount
             ) << " bits\n";

        cout << "\n===== 암호문 개수 =====\n";
        int ciphertexts_per_user = REGION_COUNT + AGE_COUNT + 1;

        cout << "사용자별: "
             << users.size() * ciphertexts_per_user
             << "개\n";

        cout << "SIMD:     "
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
