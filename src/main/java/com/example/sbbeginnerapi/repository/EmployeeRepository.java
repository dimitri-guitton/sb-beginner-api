package com.example.sbbeginnerapi.repository;

import com.example.sbbeginnerapi.model.Employee;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EmployeeRepository extends CrudRepository<Employee, Long> {

}

