
#include <seal/seal.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>

using namespace std;
using namespace seal;

// 사용자 정보
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
        throw runtime_error("CSV 파일을 열 수 없습니다: " + filename);
    }

    vector<User> users;
    string line;

    // 첫 줄(제목) 건너뛰기
    getline(file, line);

    while (getline(file, line))
    {
        if (line.empty())
        {
            continue;
        }

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
        // 1. CSV 데이터 읽기
        vector<User> users = load_users("users.csv");

        if (users.empty())
        {
            throw runtime_error("사용자 데이터가 비어 있습니다.");
        }

        cout << "총 사용자 수: "
             << users.size() << "명\n";

        // 2. BFV 암호화 설정
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
            throw runtime_error("BFV 파라미터 설정 실패");
        }

        // 3. 키 생성
        KeyGenerator keygen(context);

        SecretKey secret_key = keygen.secret_key();

        PublicKey public_key;
        keygen.create_public_key(public_key);

        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);

        Encryptor encryptor(context, public_key);
        Evaluator evaluator(context);
        Decryptor decryptor(context, secret_key);
        BatchEncoder batch_encoder(context);

        size_t slot_count = batch_encoder.slot_count();

        // 4. 검색 조건
        // 서울 = 0
        // 20대 = 20
        int search_region = 0;
        int search_age = 20;

        cout << "\n===== 검색 조건 =====\n";
        cout << "지역: 서울\n";
        cout << "연령대: 20대\n";

        // 5. 암호문 검색 결과를 합산할 변수
        Ciphertext encrypted_total;
        bool first_result = true;

        // 6. 사용자별 암호화 및 다중 조건 계산
        for (const User &user : users)
        {
            // 지역 원-핫 벡터
            vector<uint64_t> region_vector(slot_count, 0);

            if (user.region < 0 || user.region > 2)
            {
                throw runtime_error("잘못된 지역 값");
            }

            region_vector[user.region] = 1;

            // 연령대 원-핫 벡터
            // 20대=0번 슬롯, 30대=1번, 40대=2번
            vector<uint64_t> age_vector(slot_count, 0);

            int age_index = (user.age_group / 10) - 2;

            if (age_index < 0 || age_index > 2)
            {
                throw runtime_error("잘못된 연령대 값");
            }

            age_vector[age_index] = 1;

            // 평문 인코딩
            Plaintext region_plain;
            Plaintext age_plain;

            batch_encoder.encode(region_vector, region_plain);
            batch_encoder.encode(age_vector, age_plain);

            // 암호화
            Ciphertext encrypted_region;
            Ciphertext encrypted_age;

            encryptor.encrypt(region_plain, encrypted_region);
            encryptor.encrypt(age_plain, encrypted_age);

            // 검색 조건에 해당하는 슬롯만 선택
            vector<uint64_t> region_mask(slot_count, 0);
            region_mask[search_region] = 1;

            vector<uint64_t> age_mask(slot_count, 0);
            age_mask[(search_age / 10) - 2] = 1;

            Plaintext region_mask_plain;
            Plaintext age_mask_plain;

            batch_encoder.encode(region_mask, region_mask_plain);
            batch_encoder.encode(age_mask, age_mask_plain);

            Ciphertext region_match;
            Ciphertext age_match;

            evaluator.multiply_plain(
                encrypted_region,
                region_mask_plain,
                region_match
            );

            evaluator.multiply_plain(
                encrypted_age,
                age_mask_plain,
                age_match
            );

            // 선택된 슬롯을 0번 슬롯으로 이동하지 않고
            // 각 조건의 해당 슬롯을 별도로 읽을 수 있도록
            // 다음 단계에서 슬롯 회전을 사용
            //
            // 현재 검색 조건은 서울(0번 슬롯),
            // 20대(0번 슬롯)이므로 바로 곱셈 가능

            Ciphertext encrypted_match;

            evaluator.multiply(
                region_match,
                age_match,
                encrypted_match
            );

            // 암호문 크기 감소
            evaluator.relinearize_inplace(
                encrypted_match,
                relin_keys
            );

            // 검색 결과를 암호문 상태에서 합산
            if (first_result)
            {
                encrypted_total = encrypted_match;
                first_result = false;
            }
            else
            {
                evaluator.add_inplace(
                    encrypted_total,
                    encrypted_match
                );
            }
        }

        cout << "\n암호문 다중 조건 검색 완료\n";

        cout << "남은 노이즈 예산: "
             << decryptor.invariant_noise_budget(encrypted_total)
             << " bits\n";

        // 7. 최종 결과만 복호화
        Plaintext decrypted_total;

        decryptor.decrypt(
            encrypted_total,
            decrypted_total
        );

        vector<uint64_t> result;

        batch_encoder.decode(
            decrypted_total,
            result
        );

        uint64_t encrypted_count = result[0];

        // 8. 평문으로 정답 계산
        uint64_t expected_count = 0;

        for (const User &user : users)
        {
            if (user.region == search_region &&
                user.age_group == search_age)
            {
                expected_count++;
            }
        }

        cout << "\n===== 검색 결과 =====\n";

        cout << "동형암호 계산 결과: "
             << encrypted_count << "명\n";

        cout << "평문 계산 결과: "
             << expected_count << "명\n";

        cout << "\n검증 결과: "
             << (encrypted_count == expected_count
                 ? "성공" : "실패")
             << "\n";

        return encrypted_count == expected_count ? 0 : 1;
    }
    catch (const exception &e)
    {
        cerr << "오류: " << e.what() << "\n";
        return 1;
    }
}
