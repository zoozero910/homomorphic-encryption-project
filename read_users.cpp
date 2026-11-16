
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

// 사용자 한 명의 정보를 저장하는 구조체
struct User
{
    int id;
    int region;
    int age_group;
    int purchase_amount;
};

int main()
{
    // CSV 파일 열기
    ifstream file("users.csv");

    if (!file.is_open())
    {
        cerr << "users.csv 파일을 열 수 없습니다.\n";
        return 1;
    }

    vector<User> users;
    string line;

    // 첫 번째 줄(열 이름)은 건너뛰기
    getline(file, line);

    // 나머지 줄을 한 줄씩 읽기
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

    file.close();

    cout << "총 사용자 수: "
         << users.size() << "명\n\n";

    cout << "===== 처음 5명 데이터 =====\n";

    for (size_t i = 0; i < users.size() && i < 5; i++)
    {
        cout << "사용자 " << users[i].id
             << " | 지역: " << users[i].region
             << " | 연령대: " << users[i].age_group
             << " | 구매 금액: "
             << users[i].purchase_amount
             << "원\n";
    }

    return 0;
}
