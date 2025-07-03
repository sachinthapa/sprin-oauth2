#!/bin/bash
set -e

echo "Executing Bitnami OpenLDAP original entrypoint..."
#/opt/bitnami/scripts/openldap/entrypoint.sh &
/opt/bitnami/scripts/openldap/run.sh & # Run in background

# Wait for LDAP to be ready
until ldapwhoami -H ldap://localhost:1389 -D "cn=admin,dc=spring6recipes,dc=com" -w "secret" &>/dev/null; do
  echo "OpenLDAP not ready yet. Waiting..."
  sleep 2
done
echo "OpenLDAP is ready!"

sleep 2

# Enable dynlist module
ldapadd -Y EXTERNAL -H ldapi:/// << EOF
dn: cn=module,cn=config
objectClass: olcModuleList
cn: module
olcModulePath: /opt/bitnami/openldap/lib/openldap
olcModuleLoad: dynlist
EOF

# Configure dynlist overlay
ldapadd -Y EXTERNAL -H ldapi:/// << EOF
dn: olcOverlay=dynlist,olcDatabase={2}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcDynListConfig
olcOverlay: dynlist
olcDlAttrSet: groupOfURLs memberURL member
EOF

echo "Dynlist overlay configured successfully"