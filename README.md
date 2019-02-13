# README #

This module is intended as a proof of concept Mura 7+ SAML integration.

You configure the SAML endpoints and siteid here:

https://github.com/blueriver/MuraSAML/blob/master/model/handlers/handler.cfc#L3-L4

And you must place this jar in your Mura instances either your Mura 7.0 /requirements/lib or 7.1+ /core/lib directory.

https://github.com/blueriver/MuraSAML/blob/master/lib/xmlsec-2.1.2.jar

# Usage #
After deploying the this module whenever Mura wants the a user to login it will  save the user's current location as a session variable and then redirect the user to the SAML login URL.  After successfully logging in the SAML auth server the user will then be returned to the root of the Mura website where Mura will see the in-coming SAML xml and decode and validate it.  

After successful xml validation Mura will look for a user with a username that is equal to the incoming authenticated user's email. If the user does not exists it will save create a new user as a site member with no group memberships. 

The newly created user will them be available to be added to existing user groups by a Mura administrator.  

You can also pre-create a user's account by simply using the Mura admin to create and assign memberships to a user with an email address that matches a SAML account to which you want to grant access.  

The following SAML account data will be mapped to the the Mura user:

Primary Email => Username
Primary Email => Email
First Name => First Name
Last Name => Last Name
PUI = > Remote ID

If there are any other attributes that you would like sync into the Mura use please let us know and we can do that for you.

It is also configured so that Mura will redirect the user to the SAML logout url after completion of logging out of Mura.  This will prevent automatically logging a user into Mura with subsequent login requests.

After applying the update on your development server you must reload Mura in order for the the new eventHandler to get registered with the application.  At that point it will be active and you will go through your SAML authentication to login.  So it will be ready for testing.
