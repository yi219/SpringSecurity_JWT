package com.example.security.repository;

import com.example.security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

// CRUD 함수를 JpaRepository가 가지고 있음
// JpaRepository 상속 -> @Repository 어노테이션이 없어도 IoC
public interface UserRepository extends JpaRepository<User, Integer> {

}
