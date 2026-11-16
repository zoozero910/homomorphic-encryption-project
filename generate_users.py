import csv
import random

random.seed(42)

# 실험할 사용자 수
user_count = 4000

# 지역 10종
regions = list(range(10))

# 연령대 6종: 10대~60대
age_groups = [10, 20, 30, 40, 50, 60]

# CSV 파일 생성
with open("users.csv", "w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)

    writer.writerow([
        "id", "region", "age_group", "purchase_amount"
    ])

    # 가상 사용자 n명 생성
    for user_id in range(1, user_count + 1):
        region = random.choice(regions)
        age_group = random.choice(age_groups)
        purchase_amount = random.randint(1, 50) * 1000

        writer.writerow([
            user_id,
            region,
            age_group,
            purchase_amount
        ])

print(f"가상 사용자 {user_count}명 생성 완료")
print(f"지역 종류: {len(regions)}개")
print(f"연령대 종류: {len(age_groups)}개")
