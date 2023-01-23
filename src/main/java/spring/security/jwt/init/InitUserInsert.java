package spring.security.jwt.init;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import spring.security.jwt.domain.User;
import spring.security.jwt.repository.UserRepository;

import javax.annotation.PostConstruct;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;

@Component
@RequiredArgsConstructor
public class InitUserInsert {
    private final InitUserService initUserService;

    @PostConstruct
    public void init() {
        initUserService.init();
    }

    @Component
    static class InitUserService {
        @Autowired
        UserRepository userRepository;

        @Autowired
        PasswordEncoder pe;

        @Transactional
        public void init() {
            userRepository.saveAll(
               List.of(
                       User.builder()
                               .username("user")
                               .password(pe.encode("1234"))
                               .roles("USER")
                               .build(),
                       User.builder()
                               .username("manager")
                               .password(pe.encode("1234"))
                               .roles("MANAGER,USER")
                               .build(),
                       User.builder()
                               .username("admin")
                               .password(pe.encode("1234"))
                               .roles("ADMIN,MANAGER,USER")
                               .build()
               )
            );
        }
    }
}
