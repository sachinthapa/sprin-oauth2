package com.optimagrowth.license.repository;

import com.optimagrowth.license.model.License;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface LicenseRepository extends CrudRepository<License, UUID> {

	public List<License> findByOrganizationId(UUID organizationId);

	public License findByOrganizationIdAndLicenseId(UUID organizationId, UUID licenseId);

}
