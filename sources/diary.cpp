#include <iostream> // 콘솔 화면에 안내를 출력하고 사용자 입력을 받음
#include <fstream>  // 설정 정보를 파일에서 읽고 파일에 저장함
#include <string>   // 문자열 자료형을 사용함
#include <vector>   // 여러 다이어리 항목을 순서대로 저장함
#include <sstream>  // 숫자 형태의 검증값을 문자열로 바꿈

using namespace std;

// 계정 설정을 저장할 파일 이름을 한 곳에서 관리함
const string SETTINGS_FILE = "diary_settings.txt";

// 로그인, 본인 확인, 공통 비밀키 확인에 허용할 최대 입력 횟수를 정함
const int MAX_ATTEMPTS = 5;

// 로그인과 초기 설정, 본인 확인, 마스터키, 공통 다이어리 비밀키를 관리하는 클래스로 사용함
// 설정 정보의 저장과 불러오기 및 로그인 인증을 담당함
class LoginManager {
private:
    // 다이어리에 로그인할 때 사용할 비밀번호를 메모리에 보관함
    string login_password;

    // 선택한 본인 확인 질문의 번호를 1부터 5까지 저장함
    int question_number = 0;

    // 사용자가 설정한 본인 확인 답변을 보관함
    string security_answer;

    // 잠긴 다이어리 복구에 사용할 숫자 네 자리 마스터키를 보관함
    string master_key;

    // 현재 프로그램 실행 중에 사용할 공통 다이어리 비밀키를 보관함
    // 프로그램이 종료되면 메모리에서 사라지고 설정 파일에는 원문을 저장하지 않음
    string diary_secret_key;

    // 비밀키 원문 대신 저장해 두고 나중에 입력값이 같은지 비교할 검증값을 보관함
    string diary_key_verifier;

    // 문자열의 모든 문자가 허용한 ASCII 영문자, 숫자, 기호인지 확인함
    bool ContainsOnlyAllowedCharacters(const string& text) const {
        // int 반복문으로 문자열의 글자 위치를 처음부터 끝까지 확인함
        for (int i = 0; i < text.length(); i++) {
            // 현재 위치에 있는 글자 하나를 char 변수에 담아 검사함
            char ch = text[i];

            // 현재 문자가 영문 대문자 범위 A부터 Z까지인지 확인함
            bool is_uppercase = (ch >= 'A' && ch <= 'Z');

            // 현재 문자가 영문 소문자 범위 a부터 z까지인지 확인함
            bool is_lowercase = (ch >= 'a' && ch <= 'z');

            // 현재 문자가 숫자 범위 0부터 9까지인지 확인함
            bool is_digit = (ch >= '0' && ch <= '9');

            // ASCII에서 공백 다음부터 영문자 직전까지의 기호 범위를 확인함
            // 여러 범위로 나눈 이유는 중간에 있는 숫자와 영문자를 기호에 포함하지 않기 위함임
            bool is_symbol = (ch >= '!' && ch <= '/') ||
                            (ch >= ':' && ch <= '@') ||
                            (ch >= '[' && ch <= '`') ||
                            (ch >= '{' && ch <= '~');

            // 네 가지 허용 종류 어디에도 속하지 않으면 허용하지 않는 문자가 포함된 것이므로 실패 처리함
            if (!is_uppercase && !is_lowercase && !is_digit && !is_symbol) {
                return false;
            }
        }

        // 모든 문자가 허용 범위에 있으면 성공 처리함
        return true;
    }

    // 마스터키가 숫자 네 자리로만 이루어졌는지 확인함
    bool IsFourDigitMasterKey(const string& key) const {
        // 글자 수가 네 자리가 아니면 바로 실패 처리함
        if (key.length() != 4) {
            return false;
        }

        // 네 글자를 하나씩 확인해 숫자 범위 밖의 문자가 있는지 검사함
        for (string::size_type i = 0; i < key.length(); i++) {
            if (key[i] < '0' || key[i] > '9') {
                return false;
            }
        }

        // 길이와 모든 글자 검사를 통과했으므로 올바른 마스터키로 처리함
        return true;
    }

    // FNV-1a라는 정해진 계산으로 비밀키의 검증값을 만듦
    // 같은 비밀키는 항상 같은 검증값이 되므로 저장값과 비교할 때 사용함
    // 암호화나 안전한 비밀번호 해시가 아니며 서로 다른 키가 같은 값이 될 가능성도 있음을 기억함
    // 입력한 다이어리 비밀키가 저장된 키와 같은지 비교하기 위한 검증값을 계산함
    string CalculateDiaryKeyVerifier(const string& key) const {
        // FNV-1a 64비트 계산을 시작할 때 사용하는 고정 기준값으로 사용함
        // 이 숫자는 비밀키나 논스가 아니라 검증값 계산의 시작점으로 사용함
        // 숫자 끝의 ULL은 이 정수를 unsigned long long 형식으로 다루도록 지정함
        const unsigned long long FNV_OFFSET_BASIS = 14695981039346656037ULL;

        // FNV-1a 64비트 방식에서 각 글자의 값을 섞을 때 곱하는 고정 상수로 사용함
        // 사용자가 입력한 숫자가 아니라 FNV-1a 계산 규칙에 정해진 값을 사용함
        // 이 숫자 끝의 ULL도 아래 상수를 unsigned long long 형식으로 다루도록 지정함
        const unsigned long long FNV_PRIME = 1099511628211ULL;

        // 검증 계산을 FNV-1a의 시작 기준값에서 시작함
        unsigned long long verifier = FNV_OFFSET_BASIS;

        // 비밀키를 이루는 각 글자를 순서대로 검증 계산에 반영함
        for (string::size_type i = 0; i < key.length(); i++) {
            // 현재 글자 값을 검증값과 XOR 연산하여 반영함
            // XOR는 두 비트가 다르면 1, 같으면 0으로 계산하는 비트 연산임
            verifier ^= static_cast<unsigned char>(key[i]);

            // 정해진 FNV 상수를 곱해 다음 글자에 영향을 주도록 값의 비트를 섞음
            // unsigned 정수의 범위를 넘으면 2의 64제곱을 기준으로 값이 순환함
            verifier *= FNV_PRIME;
        }

        // 설정 파일 한 줄에 저장하고 문자열끼리 비교할 수 있도록 계산 결과를 문자열로 변환함
        ostringstream result;
        result << verifier;
        return result.str();
    }

    // 저장된 질문 번호에 맞는 본인 확인 질문 문장을 반환함
    string GetSecurityQuestion() const {
        if (question_number == 1) return "가장 기억에 남는 선생님은?";
        if (question_number == 2) return "가장 기억에 남는 크리스마스 선물은?";
        if (question_number == 3) return "가장 좋아하는 메뉴는?";
        if (question_number == 4) return "먹지 못하는 음식은?";
        if (question_number == 5) return "가장 좋았던 여행 장소는?";
        return "";
    }

    // 로그인 비밀번호를 최대 다섯 번 입력받아 저장된 비밀번호와 비교함
    bool EnterPassword(const string& prompt) const {
        string input_password;

        // attempt는 현재 몇 번째 입력인지 나타내며 1부터 최대 횟수까지 반복함
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            cout << prompt;
            getline(cin, input_password);

            // 입력한 문자열과 저장된 로그인 비밀번호가 같으면 인증 성공 처리함
            if (CheckLoginPassword(input_password)) {
                cout << "비밀번호가 확인되었습니다.\n";
                return true;
            }

            // 현재 입력을 포함해 한 번 사용했으므로 최대 횟수에서 attempt를 뺀 값을 안내함
            cout << "비밀번호가 틀렸습니다. 남은 횟수: "
                 << MAX_ATTEMPTS - attempt << "회\n";
        }

        return false;
    }

    // 선택한 본인 확인 질문을 보여주고 답변을 최대 다섯 번 확인함
    bool VerifySecurityAnswer() const {
        string input_answer;

        cout << "\n본인 확인 질문: " << GetSecurityQuestion() << "\n";

        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            cout << "답변을 입력하세요: ";
            getline(cin, input_answer);

            if (input_answer == security_answer) {
                cout << "본인 확인에 성공했습니다.\n";
                return true;
            }

            cout << "답변이 틀렸습니다. 남은 횟수: "
                 << MAX_ATTEMPTS - attempt << "회\n";
        }

        return false;
    }

public:
    // 설정 파일에서 저장해 둔 설정 정보를 정해진 순서대로 불러옴
    // 파일의 줄 순서는 로그인 비밀번호, 질문 번호, 답변, 마스터키, 다이어리 비밀키 검증값으로 정함
    // 현재 코드는 다이어리 비밀키 원문 대신 검증값만 저장하고 불러옴
    // 로그인 비밀번호, 본인 확인 답변, 마스터키는 현재 설정 파일에 입력한 문자열 그대로 저장함
    bool LoadSettings() {
        // 설정 파일을 읽기 모드로 엶
        ifstream input_file(SETTINGS_FILE);

        // 파일이 없거나 열 수 없으면 저장된 설정이 없는 것으로 처리함
        if (!input_file.is_open()) {
            return false;
        }

        // 첫 번째 줄에서 로그인 비밀번호를 읽으며 없거나 빈 값이면 설정 불러오기를 실패 처리함
        if (!getline(input_file, login_password) || login_password == "") {
            return false;
        }

        // 두 번째 줄은 본인 확인 질문 번호를 문자열로 읽은 뒤 정수 값으로 바꿈
        string saved_question_number;
        if (getline(input_file, saved_question_number)) {
            if (saved_question_number == "1") question_number = 1;
            else if (saved_question_number == "2") question_number = 2;
            else if (saved_question_number == "3") question_number = 3;
            else if (saved_question_number == "4") question_number = 4;
            else if (saved_question_number == "5") question_number = 5;

            // 다음 줄에서 본인 확인 답변을 읽음
            getline(input_file, security_answer);

            // 그 다음 줄에서 마스터키를 읽음
            getline(input_file, master_key);

            // 마지막 줄에서 다이어리 비밀키 검증값을 읽음
            // 이전 설정 파일처럼 이 줄이 없으면 빈 값으로 남아 초기 설정에서 새로 입력받음
            getline(input_file, diary_key_verifier);
        }

        // 파일의 주요 설정을 읽었으므로 성공 처리함
        return true;
    }

    // 설정 정보를 정해진 줄 순서대로 설정 파일에 저장함
    // 다이어리 비밀키 원문 대신 검증값을 저장함
    bool SaveSettings() const {
        // 같은 이름의 설정 파일을 쓰기 모드로 엶
        // 기존 내용은 새 설정으로 덮어씀
        ofstream output_file(SETTINGS_FILE);

        if (!output_file.is_open()) {
            cout << "설정 파일을 열 수 없습니다.\n";
            return false;
        }

        // 첫 번째 줄에 로그인 비밀번호를 씀
        output_file << login_password << '\n';

        // 두 번째 줄에 본인 확인 질문 번호를 씀
        output_file << question_number << '\n';

        // 세 번째 줄에 본인 확인 답변을 씀
        output_file << security_answer << '\n';

        // 네 번째 줄에 마스터키를 씀
        output_file << master_key << '\n';

        // 다섯 번째 줄에 다이어리 비밀키 원문 대신 검증값을 씀
        output_file << diary_key_verifier << '\n';

        if (!output_file) {
            cout << "설정 정보를 파일에 저장하지 못했습니다.\n";
            return false;
        }

        return true;
    }

    // 최초 실행 때 로그인 비밀번호를 조건에 맞게 두 번 입력받아 설정함
    bool SetLoginPassword() {
        string password;
        string confirm_password;

        cout << "\n[로그인 비밀번호 조건]\n";
        cout << "- 6자 이상\n";
        cout << "- 공백 불가\n";
        cout << "- 영문 대소문자, 숫자, 기호만 사용 가능\n\n";

        while (true) {
            cout << "로그인 비밀번호를 설정하세요: ";
            getline(cin, password);

            if (password == "") {
                cout << "비밀번호는 비워둘 수 없습니다. 다시 입력하세요.\n\n";
                continue;
            }

            if (password.length() < 6) {
                cout << "비밀번호는 6자 이상이어야 합니다. 다시 입력하세요.\n\n";
                continue;
            }

            if (!ContainsOnlyAllowedCharacters(password)) {
                cout << "영문 대소문자, 숫자, 기호만 사용할 수 있습니다. 공백과 한글은 입력할 수 없습니다.\n\n";
                continue;
            }

            cout << "비밀번호를 한 번 더 입력하세요: ";
            getline(cin, confirm_password);

            if (password == confirm_password) {
                login_password = password;
                cout << "로그인 비밀번호 설정이 완료되었습니다.\n";
                return true;
            }

            cout << "두 비밀번호가 일치하지 않습니다. 처음부터 다시 설정하세요.\n\n";
        }
    }

    // 다섯 가지 질문 중 하나를 선택하고 그 답을 설정함
    bool SetSecurityQuestionAndAnswer() {
        string choice;

        cout << "\n[본인 확인 질문 선택]\n";
        cout << "1. 가장 기억에 남는 선생님\n";
        cout << "2. 가장 기억에 남는 크리스마스 선물\n";
        cout << "3. 가장 좋아하는 메뉴\n";
        cout << "4. 먹지 못하는 음식\n";
        cout << "5. 가장 좋았던 여행 장소\n";

        while (true) {
            cout << "질문 번호를 선택하세요 (1~5): ";
            getline(cin, choice);

            if (choice == "1") question_number = 1;
            else if (choice == "2") question_number = 2;
            else if (choice == "3") question_number = 3;
            else if (choice == "4") question_number = 4;
            else if (choice == "5") question_number = 5;
            else {
                cout << "1부터 5까지의 번호를 입력하세요.\n";
                continue;
            }
            break;
        }

        while (true) {
            cout << GetSecurityQuestion() << "\n답변을 설정하세요: ";
            getline(cin, security_answer);

            if (security_answer != "") {
                cout << "본인 확인 질문과 답변이 설정되었습니다.\n";
                return true;
            }
            cout << "답변은 비워둘 수 없습니다. 다시 입력하세요.\n";
        }
    }

    // 잠긴 다이어리 복구에 사용할 숫자 네 자리 마스터키를 설정함
    bool SetMasterKey() {
        string key;
        string confirm_key;

        while (true) {
            cout << "\n잠긴 다이어리 복구에 사용할 숫자 4자리 마스터키를 설정하세요: ";
            getline(cin, key);

            if (!IsFourDigitMasterKey(key)) {
                cout << "마스터키는 0~9 숫자 4자리로 입력하세요.\n";
                continue;
            }

            cout << "마스터키를 한 번 더 입력하세요: ";
            getline(cin, confirm_key);

            if (key == confirm_key) {
                master_key = key;
                cout << "마스터키 설정이 완료되었습니다.\n";
                return true;
            }

            cout << "두 마스터키가 일치하지 않습니다. 다시 설정하세요.\n";
        }
    }

    // 모든 다이어리에 공통으로 사용할 비밀키를 한 번 설정하고 검증값을 만듦
    // 입력한 비밀키 원문은 현재 실행 중에만 메모리에 보관함
    bool SetDiarySecretKey() {
        string key;
        string confirm_key;

        cout << "\n[다이어리 공통 비밀키 조건]\n";
        cout << "- 6자 이상\n";
        cout << "- 공백 불가\n";
        cout << "- 영문 대소문자, 숫자, 기호만 사용 가능\n";
        cout << "- 로그인 비밀번호와 다른 값으로 설정\n\n";

        while (true) {
            cout << "모든 다이어리에 사용할 비밀키를 설정하세요: ";
            getline(cin, key);

            if (key == "") {
                cout << "비밀키는 비워둘 수 없습니다.\n";
                continue;
            }

            if (key.length() < 6) {
                cout << "비밀키는 6자 이상이어야 합니다.\n";
                continue;
            }

            if (!ContainsOnlyAllowedCharacters(key)) {
                cout << "영문 대소문자, 숫자, 기호만 사용할 수 있습니다. 공백과 한글은 입력할 수 없습니다.\n";
                continue;
            }

            if (key == login_password) {
                cout << "로그인 비밀번호와 다른 값으로 설정하세요.\n";
                continue;
            }

            cout << "비밀키를 한 번 더 입력하세요: ";
            getline(cin, confirm_key);

            if (key == confirm_key) {
                diary_secret_key = key;
                diary_key_verifier = CalculateDiaryKeyVerifier(key);
                cout << "공통 다이어리 비밀키 설정이 완료되었습니다.\n";
                return true;
            }

            cout << "두 비밀키가 일치하지 않습니다. 다시 설정하세요.\n";
        }
    }

    // 설정 파일에 저장된 검증값과 입력값을 비교해 현재 실행에서 사용할 비밀키를 확인함
    // 성공하면 입력값을 메모리에 보관하므로 같은 실행 중에는 다시 묻지 않음
    bool EnsureDiarySecretKeyForSession() {
        // 이미 이번 실행 중 비밀키를 설정했거나 확인했다면 다시 묻지 않음
        if (diary_secret_key != "") {
            return true;
        }

        // 비교할 검증값이 없으면 설정이 완료되지 않은 상태이므로 실패 처리함
        if (diary_key_verifier == "") {
            cout << "다이어리 비밀키 검증 정보가 없습니다. 초기 설정을 확인하세요.\n";
            return false;
        }

        // 사용자가 입력한 공통 비밀키를 잠시 보관할 문자열임
        string input_key;

        // 비밀키를 최대 다섯 번 입력받아 검증값이 일치하는지 확인함
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            cout << "다이어리 공통 비밀키를 입력하세요: ";
            getline(cin, input_key);

            // 입력값에서 계산한 검증값이 설정 때 저장한 값과 같으면 올바른 비밀키임
            if (CalculateDiaryKeyVerifier(input_key) == diary_key_verifier) {
                // 확인한 원문을 이번 실행 동안 메모리에 보관해 이후 메모 작성 때 재사용함
                diary_secret_key = input_key;
                cout << "다이어리 비밀키가 확인되었습니다. 이번 실행 중에는 다시 입력하지 않아도 됩니다.\n";
                return true;
            }

            cout << "비밀키가 틀렸습니다. 남은 횟수: "
                 << MAX_ATTEMPTS - attempt << "회\n";
        }

        cout << "비밀키 확인에 실패했습니다. 다이어리 작성을 취소합니다.\n";
        return false;
    }

    // 이후 암호화와 복호화 기능에서 현재 실행 중 사용할 공통 비밀키를 가져갈 수 있게 반환함
    string GetDiarySecretKey() const {
        return diary_secret_key;
    }

    // 최초 설정 흐름에서 필요한 항목을 정해진 순서로 입력받고 설정 파일에 저장함
    bool SetupInitialSettings() {
        // 각 설정이 이미 준비되었는지 확인해 초기 설정을 다시 진행할지 결정함
        bool needs_login_password = (login_password == "");
        bool needs_security_answer = (question_number < 1 || question_number > 5 || security_answer == "");
        bool needs_master_key = !IsFourDigitMasterKey(master_key);
        bool needs_diary_secret_key = (diary_key_verifier == "");

        // 네 가지 설정이 모두 존재하면 초기 설정 화면을 건너뜀
        if (!needs_login_password && !needs_security_answer &&
            !needs_master_key && !needs_diary_secret_key) {
            return true;
        }

        // 초기 설정의 시작을 알리고 필요한 설정을 순서대로 진행함
        cout << "\n=== 초기 설정 단계 ===\n";
        cout << "다이어리 사용에 필요한 항목을 순서대로 설정합니다.\n";
        cout << "이미 설정된 항목은 건너뜁니다.\n";

        // 1번 단계에서 다이어리에 로그인할 때 사용할 비밀번호를 설정함
        if (needs_login_password) {
            cout << "\n1. 로그인 비밀번호를 설정하세요.\n";
            cout << "   다이어리에 로그인할 때 사용됩니다.\n";
            if (!SetLoginPassword()) {
                return false;
            }
        }

        // 2번 단계에서 질문을 고르고 로그인 비밀번호를 5회 틀렸을 때 사용할 답변을 설정함
        if (needs_security_answer) {
            cout << "\n2. 본인 확인 질문과 답변을 설정하세요.\n";
            cout << "   로그인 비밀번호를 5회 틀렸을 때 사용됩니다.\n";
            if (!SetSecurityQuestionAndAnswer()) {
                return false;
            }
        }

        // 3번 단계에서 잠긴 다이어리를 확인하고 복구할 때 사용할 마스터키를 설정함
        if (needs_master_key) {
            cout << "\n3. 마스터키를 설정하세요.\n";
            cout << "   잠긴 다이어리를 확인하거나 복구할 때 사용됩니다.\n";
            if (!SetMasterKey()) {
                return false;
            }
        }

        // 4번 단계에서 메모 본문을 암호화하고 읽을 때 사용할 공통 비밀키를 설정함
        if (needs_diary_secret_key) {
            cout << "\n4. 다이어리 비밀키를 설정하세요.\n";
            cout << "   메모 본문을 암호화하고 읽을 때 사용됩니다.\n";
            if (!SetDiarySecretKey()) {
                return false;
            }
        }

        // 설정한 네 항목을 설정 파일에 저장함
        return SaveSettings();
    }

    // 전달된 문자열이 저장된 로그인 비밀번호와 같은지 확인함
    bool CheckLoginPassword(const string& input) const {
        return input == login_password;
    }

    // 로그인 비밀번호를 다섯 번 틀리면 본인 확인을 진행하고 통과하면 다시 로그인함
    bool Login() const {
        cout << "\n=== 로그인 ===\n";

        if (EnterPassword("로그인 비밀번호를 입력하세요: ")) {
            return true;
        }

        cout << "\n비밀번호 입력 5회 실패. 본인 확인을 진행합니다.\n";
        if (!VerifySecurityAnswer()) {
            cout << "본인 확인 5회 실패로 다이어리 접근을 차단합니다.\n";
            return false;
        }

        cout << "본인 확인에 성공했습니다. 로그인 비밀번호 입력 기회를 다시 제공합니다.\n";
        if (!EnterPassword("로그인 비밀번호를 다시 입력하세요: ")) {
            cout << "비밀번호 재입력 5회 실패로 다이어리 접근을 차단합니다.\n";
            return false;
        }

        return true;
    }
};

// 다이어리 한 편에 해당하는 데이터를 묶어 표현하는 자료형으로 사용함
// DiaryManager의 vector 안에 여러 DiaryEntry 객체를 저장해 관리함
// 현재는 번호, 제목, 본문, 잠금 상태를 관리하며 항목별 비밀키는 두지 않음
class DiaryEntry {
// private 영역은 항목의 내부 데이터를 외부에서 직접 바꾸지 못하게 감춤
private:
    // 다이어리 항목을 구분하는 번호를 저장함
    int entry_number;

    // 다이어리 제목을 저장함
    string title;

    // 다이어리 본문을 저장함
    string content;

    // 항목이 잠겨 있는지 저장하며 false는 일반 상태를 의미함
    bool locked;

// public 영역은 다른 클래스가 항목을 만들고 필요한 정보를 읽을 수 있게 함
public:
    // 번호, 제목, 본문을 받아 각 멤버 변수를 초기화하고 처음 상태를 일반으로 설정함
    DiaryEntry(int number, const string& entry_title, const string& entry_content)
        : entry_number(number), title(entry_title), content(entry_content),
          locked(false) {}

    // 항목을 선택하거나 표시할 때 사용할 번호를 반환함
    int GetEntryNumber() const {
        return entry_number;
    }

    // 목록에 표시할 제목을 반환함
    string GetTitle() const {
        return title;
    }

    // 열람 기능에서 사용할 본문을 반환함
    string GetContent() const {
        return content;
    }

    // 목록 표시와 접근 확인에 사용할 잠금 상태를 반환함
    bool IsLocked() const {
        return locked;
    }
};

// 여러 다이어리 항목을 모아 관리하고 목록 표시와 새 항목 작성을 담당하는 클래스로 사용함
// LoginManager와 연결되어 모든 항목에서 공통으로 쓸 비밀키 확인을 요청함
class DiaryManager {
// private 영역은 목록과 내부 처리 과정을 외부에서 직접 변경하지 못하게 감춤
private:
    // 여러 다이어리 항목을 순서대로 관리함
    vector<DiaryEntry> entries;

    // 로그인 관리자 객체를 참조해 공통 비밀키 확인을 요청함
    // 참조자로 연결하므로 DiaryManager가 별도의 LoginManager 복사본을 만들지 않음
    LoginManager& login_manager;

    // 새 항목을 만들 때 부여할 번호를 저장하며 항목 생성 후 1씩 증가함
    int next_entry_number = 1;

    // 공통 비밀키가 확인되었는지 확인한 뒤 제목과 본문을 새 항목으로 추가함
    void AddDiary() {
        string title;
        string content;

        if (!login_manager.EnsureDiarySecretKeyForSession()) {
            return;
        }

        while (true) {
            cout << "다이어리 제목을 입력하세요: ";
            getline(cin, title);
            if (title != "") break;
            cout << "제목은 비워둘 수 없습니다.\n";
        }

        while (true) {
            cout << "다이어리 본문을 입력하세요: ";
            getline(cin, content);
            if (content != "") break;
            cout << "본문은 비워둘 수 없습니다.\n";
        }

        // 전달한 정보로 DiaryEntry 객체를 만들고 vector의 마지막에 추가함
        entries.push_back(DiaryEntry(next_entry_number, title, content));
        cout << "다이어리 항목을 추가했습니다. 번호: " << next_entry_number << "\n";
        next_entry_number++;
    }

    // vector에 저장된 모든 다이어리의 번호, 제목, 상태를 차례대로 출력함
    void ShowDiaryList() const {
        if (entries.empty()) {
            cout << "작성된 다이어리가 없습니다.\n";
            return;
        }

        cout << "\n번호\t제목\t\t상태\n";
        // vector의 첫 번째 항목부터 마지막 항목까지 순서대로 출력함
        for (vector<DiaryEntry>::size_type i = 0; i < entries.size(); i++) {
            cout << entries[i].GetEntryNumber() << "\t"
                 << entries[i].GetTitle() << "\t\t"
                 << (entries[i].IsLocked() ? "잠김" : "일반") << "\n";
        }
    }

// public 영역은 main 함수에서 메뉴를 시작할 수 있도록 공개함
public:
    // 전달받은 LoginManager를 참조자로 연결해 공통 비밀키 확인에 사용하도록 초기화함
    explicit DiaryManager(LoginManager& manager) : login_manager(manager) {}

    // 메뉴를 반복해 표시하고 입력에 따라 목록 보기, 새 항목 작성, 종료를 처리함
    void RunMenu() {
        string choice;

        while (true) {
            cout << "\n=== 다이어리 메뉴 ===\n";
            cout << "1. 다이어리 목록 보기\n";
            cout << "+. 새 다이어리 작성\n";
            cout << "0. 종료\n";
            cout << "선택: ";
            getline(cin, choice);

            if (choice == "1") {
                ShowDiaryList();
            } else if (choice == "+") {
                AddDiary();
            } else if (choice == "0") {
                cout << "프로그램을 종료합니다.\n";
                return;
            } else {
                cout << "올바른 메뉴 번호를 입력하세요.\n";
            }
        }
    }
};

int main() {
    // 프로그램 전체에서 로그인과 설정을 관리할 LoginManager 객체를 만듦
    LoginManager login_manager;

    // 기존 설정 파일을 읽고 성공 여부에 따라 안내 문구를 출력함
    if (login_manager.LoadSettings()) {
        cout << "저장된 설정을 불러왔습니다.\n";
    }

    // 처음 실행했거나 설정에 빠진 값이 있으면 입력받아 파일에 저장함
    if (!login_manager.SetupInitialSettings()) {
        return 1;
    }

    cout << "초기 설정 확인이 완료되었습니다.\n";

    // 로그인에 성공한 경우에만 다이어리 관리 메뉴에 들어감
    if (login_manager.Login()) {
        cout << "로그인에 성공했습니다.\n";

        // 로그인 관리자와 연결된 다이어리 관리 객체를 만들고 메뉴를 시작함
        DiaryManager diary_manager(login_manager);
        diary_manager.RunMenu();
    } else {
        cout << "로그인할 수 없습니다. 프로그램을 종료합니다.\n";
    }

    return 0;
}
