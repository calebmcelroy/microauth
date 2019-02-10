# microauth

### Under Development (Not Stable) 

microauth is designed to be used as a microservice for authenticating users. 

**Flexible & Configurable**

Designed to flexible and configurable but 
yet provides a base of secure logic for any auth server. A type called _RoleConfig_ is used to configure your needed roles 
and their capability. Also, abstracts for external components like database, IP geolocation provider, password hashing, custom emails, & 
more are provided to provide flexibility if the defaults do not fit your needs. 

**Features**

This package aims at providing a high level of security and contains common security features such as: 

- Two Factor Authentication
- API Brute Force Protection with ReCaptcha
- New Device Verification
- New Location Verification
- Login Notifications
- Password Reset