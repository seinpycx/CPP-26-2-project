#include <iostream>
#include <string>

using namespace std;

class LoginManager {
private:
    string loginPassword;

    // 영문 대소문자, 숫자, 기호만 포함되어 있는지 확인한다.
    bool containsOnlyAllowedCharacters(const string& text) const {
        for (string::size_type i = 0; i < text.length(); i++) {
            unsigned char ch = static_cast<unsigned char>(text[i]);

            bool isUppercase = (ch >= 'A' && ch <= 'Z');
            bool isLowercase = (ch >= 'a' && ch <= 'z');
            bool isDigit = (ch >= '0' && ch <= '9');
            bool isSymbol = (ch >= '!' && ch <= '/') ||
                            (ch >= ':' && ch <= '@') ||
                            (ch >= '[' && ch <= '`') ||
                            (ch >= '{' && ch <= '~');

            if (!isUppercase && !isLowercase && !isDigit && !isSymbol) {
                return false;
            }
        }
        return true;
    }

public:
    // 처음 사용할 로그인 비밀번호를 설정한다.
    void setLoginPassword() {
        string password;
        string confirmPassword;

        cout << "\n[비밀번호 설정 조건]\n";
        cout << "- 6자 이상\n";
        cout << "- 공백 불가\n";
        cout << "- 영문 대소문자, 숫자, 기호만 사용 가능 (공백·한글 불가)\n\n";

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

            if (!containsOnlyAllowedCharacters(password)) {
                cout << "영문 대소문자, 숫자, 기호만 사용할 수 있습니다. 공백과 한글은 입력할 수 없습니다. 다시 입력하세요.\n\n";
                continue;
            }

            cout << "비밀번호를 한 번 더 입력하세요: ";
            getline(cin, confirmPassword);

            if (password == confirmPassword) {
                loginPassword = password;
                cout << "로그인 비밀번호 설정이 완료되었습니다.\n";
                return;
            }

            cout << "두 비밀번호가 일치하지 않습니다. 처음부터 다시 설정하세요.\n\n";
        }
    }

    // 나중에 로그인 기능에서 입력값을 확인할 때 사용할 함수
    bool checkLoginPassword(const string& input) const {
        return input == loginPassword;
    }
};

int main() {
    LoginManager loginManager;

    cout << "=== 보안 다이어리 초기 설정 ===\n";
    loginManager.setLoginPassword();

    cout << "\n현재 실행 중인 프로그램에 비밀번호가 설정되었습니다.\n";
    return 0;
}
