package com.wso2telco.commonutils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.keymgt.service.TokenValidationContext;
import org.wso2.carbon.apimgt.keymgt.token.JWTGenerator;

import java.util.HashMap;
import java.util.Map;

public class CustomTokenGenerator extends JWTGenerator {
	private static final String END_USER = "enduser";
	private static final String TENANT_IDENTIFIER = "@carbon.super";
	private static final String MOBILE = "mobile";


    private static Log log = LogFactory.getLog(CustomTokenGenerator.class);
	
    public Map<String, String> populateStandardClaims(TokenValidationContext validationContext)
            throws APIManagementException {
        Map<String, String> claims = super.populateStandardClaims(validationContext);
        boolean isApplicationToken =
                validationContext.getValidationInfoDTO().getUserType().equalsIgnoreCase(APIConstants.ACCESS_TOKEN_USER_TYPE_APPLICATION) ? true : false;
        String dialect = getDialectURI();
        if (claims.get(dialect + "/" + END_USER) != null) {
            if (isApplicationToken) {
                claims.put(dialect + "/" + END_USER, "null");
                claims.put(dialect + "/enduserTenantId", "null");
            } else {
                String enduser = claims.get(dialect + "/" + END_USER);
                if (enduser.endsWith(TENANT_IDENTIFIER)) {
                    enduser = enduser.replace(TENANT_IDENTIFIER, "");
                    claims.put(dialect + "/" + END_USER, enduser);
                }
            }
        }

        return claims;

    }

    public Map<String, String> populateCustomClaims(TokenValidationContext validationContext) throws APIManagementException {
        Map<String,String> customClaims = new HashMap<String, String>();
        String trustedstatus = "";
        String mobile = validationContext.getValidationInfoDTO().getEndUserName();
        if(!trustedstatus.equals("")) {
            if (mobile.endsWith(TENANT_IDENTIFIER)) {
                mobile = mobile.replace(TENANT_IDENTIFIER, "");
            }
            customClaims.put(MOBILE, mobile);
        } 
        return customClaims;
    }

}
