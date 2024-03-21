package S10P22D204.authentication.entity;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

@Getter
@Setter
@Table("users")
public class Users {

    @Id
    private Long id;

    @Column("provider_id")
    private String providerId;

    @Column("provider")
    private Provider provider;

    @Column("internal_id")
    private String internalId;

    @Column("nickname")
    private String nickname;

    @Column("survey_status")
    private Boolean surveyStatus = false;

    @Column("created_at")
    @CreatedDate
    private LocalDateTime createdAt;

    @Column("updated_at")
    @LastModifiedDate
    private LocalDateTime updatedAt;

    @Column("is_deleted")
    private boolean isDeleted = false;
}