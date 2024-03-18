package S10P22D204.authentication.common.exception;


import lombok.Getter;

@Getter
public enum ExceptionType {

    // locked
    FAILED_TO_ACQUIRE_LOCK(409, "락 획득에 실패했습니다."),
    INTERRUPTED_WHILE_WAITING_FOR_LOCK(500, "락을 기다리는 동안 인터럽트가 발생하였습니다"),

    // users
    NOT_FOUND_USER(401, "등록된 사용자가 없습니다."),
    NOT_VALID_USER(400, "등록된 사용자가 유효하지 않습니다."),
    ALREADY_EXIST_USER_EMAIL(409, "이미 존재하는 이메일입니다."),
    NOT_MATCHING_INFO(400, "회원 정보가 일치하지 않습니다."),
    NO_TOKEN(401, "토큰이 없습니다."),
    NOT_VALID_TOKEN(401, "토큰이 유효하지 않습니다."),
    NOT_VALID_ROLE(403, "유저 권한이 부족합니다."),
    TOKEN_EXPIRED(401, "토큰이 만료되었습니다."),
    EMAIL_REQUEST_LIMIT_EXCEEDED(429, "이메일 요청 한도를 초과했습니다. 잠시 후 다시 시도해주세요."),
    PASSWORD_REQUEST_LIMIT_EXCEEDED(429, "비밀번호 요청 한도를 초과하였습니다."),
    AUTHENTICATION_REQUEST_LIMIT_EXCEEDED(429, "인증요청 한도를 초과하였습니다."),
    OUTSIDE_PASSWORD_CHANGE_REQUEST_LIMIT_EXCEEDED(429, "서버 밖 비밀번호 변경 요청 한도를 초과하였습니다."),
    VERIFICATION_CODE_EXPIRED(400, "인증 코드가 만료되었습니다. 새로운 코드를 요청해주세요."),
    VERIFICATION_CODE_MISMATCH(400, "인증 코드가 일치하지 않습니다. 다시 시도해주세요."),
    VERIFICATION_CODE_NOT_FOUND(400, "인증 코드를 찾을 수 없습니다. 다시 시도하거나 새로운 코드를 요청해주세요."),
    NICKNAME_EMPTY(400, "닉네임이 비어있습니다."),
    NICKNAME_TOO_LONG(400, "닉네임이 너무 깁니다. 최대 50자를 초과할 수 없습니다."),
    NICKNAME_DUPLICATE(409, "닉네임이 중복되었습니다."),
    NICKNAME_UNAUTHORIZED(401, "닉네임이 유효하지 않습니다."),
    INVALID_LOGIN(401, "아이디 또는 비밀번호가 일치하지 않습니다."),
    ACCOUNT_LOCKED(403, "계정이 잠겨있습니다."),
    SELF_SUBSCRIPTION_ATTEMPTED(400, "자기 자신을 구독할 수 없습니다."),
    ALREADY_WITHDRAWN_USER(409, "이미 탈퇴한 사용자입니다."),
    ALREADY_FOLLOWING(409, "이미 팔로우 하고있는 사용자입니다."),

    ;

    private final int code;
    private final String msg;

    ExceptionType (int code, String msg) {
        this.code = code;
        this.msg = msg;
    }
}
