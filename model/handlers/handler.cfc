<cfcomponent extends="mura.cfobject" output="false">
<cfscript>
	application.secureURL="https://YOUR-SAML-SEVER/adfs/ls/idpinitiatedsignon.aspx?loginToRp=#cgi.SERVER_NAME#";
	application.postLogoutURL="https://YOUR-SAML-SEVER/adfs/ls/?wa=wsignout1.0";
	variables.defaultSiteid="default";

	//session.returnURL: where to go AFTER logging in at the application.secureURL url.

	function onGlobalRequestStart($){

		if(isdefined('form.SAMLResponse')){
			var samlData=$.getBean('samlService').processResponse(form.SAMLResponse,true);

			if(samlData.authvalid){

				var userData={};

				userData.fname=samlData.user['first name'][1];
				userData.lname=samlData.user['last name'][1];
				userData.email=samlData.user['primary email'][1];
				userData.username=userData.email;
				userData.remoteid=samlData.user.pui[1];

				//var SignatureValue=SAMLResponse['samlp:Response']['assertion']['ds:Signature']['ds:SignatureValue'];
				//WriteDump(SAMLResponse['samlp:Response']['assertion']['ds:Signature']['ds:SignedInfo']['ds:Reference']['ds:DigestValue']);

				arguments.$.event('siteid',variables.defaultSiteid);

				//check to see if the user has previous login into the system
				var userBean=$.getBean('user').loadBy(username=userData.username);

				if(!userBean.exists()
						|| 	(
							userData.fname != userBean.get('fname')
							|| userData.lname != userBean.get('lname')
							|| userData.remoteid != userBean.get('remoteid')
						)
					){
					if(!userBean.exists()){
						userBean.setPassword(createUUID());
					}
					userBean.set(userData).save();
				}

				//if(userBean.exists()){
					$.getBean("userUtility").loginByUserID(userBean.getUserID(),variables.defaultSiteid);

					//set siteArray
					if(session.mura.isLoggedIn){
						session.siteArray=[];
						settingsManager = $.getBean("settingsManager");
						for( site in settingsManager.getSites()) {
							if(application.permUtility.getModulePerm("00000000000000000000000000000000000",site)){
								arrayAppend(session.siteArray,site);
							}
						}
					}

					param name="session.returnurl" default="/";

					if(!len(session.returnURL)){
						session.returnURL="/";
					}

					location(session.returnurl,false);
				//}
			} else {
				WriteDump(samlData);abort;
			}
		}
	}

	function onApplicationLoad($){
			var rsSites=getBean('settingsManager').getList();
			var pluginManager=getBean('pluginManager');
			var handler=new mura.cfobject();
			handler.injectMethod("onAdminRequestStart",_onAdminRequestStart);
			handler.injectMethod("standardRequireLoginHandler",_standardRequireLoginHandler);
			handler.injectMethod("onRenderStart",_onRenderStart);
			handler.injectMethod("onAfterSiteLogout",_onAfterSiteLogout);

			if(rsSites.recordcount){
				for(var i=1;i<=rsSites.recordcount;i++) {
					pluginManager.addEventHandler(component=handler,siteid=rsSites.siteID[i]);
				}
			}
	}

	function _onAdminRequestStart($){
		if( find('local',cgi.HTTP_HOST) or find('offline',cgi.HTTP_HOST) or structKeyExists(url, 'samloverride') ) {
			// Normal admin login if on the local development site or if override param passed in
			return;
		}

		if( len($.event('muraAction')) && $.event('muraAction')=='core:clogin.main' ) {
			session.returnURL=$.event('returnURL');

			if($.currentUser().isLoggedIn() && !$.currentUser().isPrivateUser()){
				location($.getBean('settingsManager').getSite(session.siteid).getRootPath(complete=true),false);
			}

			if(!len(session.returnURL)){
				session.returnURL=$.globalConfig().getAdminPath(complete=true);
			}

			if(request.muraAPIRequest){
				request.muraJSONRedirectURL=application.secureURL;
			} else {
				location(application.secureURL,false);
			}
		}
	}

	function _standardRequireLoginHandler($){
		if( find('local',cgi.HTTP_HOST) or find('offline',cgi.HTTP_HOST) or structKeyExists(url, 'samloverride') ) {
			// Normal admin login if on the local development site or if override param passed in
			return;
		}

		session.returnURL=$.getCurrentURL();
		if(request.muraAPIRequest){
			request.muraJSONRedirectURL=application.secureURL;
		} else {
			location(application.secureURL,false);
		}
	}

	function _onRenderStart($){
		if( find('local',cgi.HTTP_HOST) or find('offline',cgi.HTTP_HOST) or structKeyExists(url, 'samloverride') ) {
			// Normal admin login if on the local development site or if override param passed in
			return;
		}

		if($.event('display')=='login'){
			session.returnURL=$.event('returnURL');
			if(request.muraAPIRequest){
				request.muraJSONRedirectURL=application.secureURL;
			} else {
				location(application.secureURL,false);
			}
		}
	}

	function _onAfterSiteLogout($){

		if(request.muraAPIRequest){
			request.muraJSONRedirectURL=application.postLogoutURL;
		} else {
			location($.siteConfig().getRootPath(complete=true),false);
		}

	}

</cfscript>
</cfcomponent>
