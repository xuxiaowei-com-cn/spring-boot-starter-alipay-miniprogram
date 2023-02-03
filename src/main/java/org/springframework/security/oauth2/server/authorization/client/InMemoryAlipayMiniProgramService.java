package org.springframework.security.oauth2.server.authorization.client;

/*-
 * #%L
 * spring-boot-starter-alipay-miniprogram
 * %%
 * Copyright (C) 2022 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import com.alipay.api.AlipayApiException;
import com.alipay.api.AlipayClient;
import com.alipay.api.DefaultAlipayClient;
import com.alipay.api.request.AlipaySystemOauthTokenRequest;
import com.alipay.api.request.AlipayUserInfoShareRequest;
import com.alipay.api.response.AlipaySystemOauthTokenResponse;
import com.alipay.api.response.AlipayUserInfoShareResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AlipayMiniProgramAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.exception.AppidAlipayMiniProgramException;
import org.springframework.security.oauth2.server.authorization.properties.AlipayMiniProgramProperties;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AlipayMiniProgramEndpointUtils;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AlipayMiniProgramEndpointUtils.AUTH_ALIPAY_SYSTEM_OAUTH_TOKEN_URI;
import static org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AlipayMiniProgramEndpointUtils.AUTH_ALIPAY_USER_INFO_SHARE_URI;

/**
 * 支付宝小程序 账户服务接口 基于内存的实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class InMemoryAlipayMiniProgramService implements AlipayMiniProgramService {

	private final AlipayMiniProgramProperties alipayMiniProgramProperties;

	public InMemoryAlipayMiniProgramService(AlipayMiniProgramProperties alipayMiniProgramProperties) {
		this.alipayMiniProgramProperties = alipayMiniProgramProperties;
	}

	/**
	 * 认证信息
	 * @param appid AppID(小程序ID)
	 * @param userId 用户唯一标识
	 * @param details 登录信息
	 * @return 返回 认证信息
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String userId,
			Object credentials) throws OAuth2AuthenticationException {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(alipayMiniProgramProperties.getDefaultRole());
		authorities.add(authority);
		User user = new User(userId, "", authorities);

		UsernamePasswordAuthenticationToken principal = UsernamePasswordAuthenticationToken.authenticated(user, null,
				user.getAuthorities());

		AlipayMiniProgramAuthenticationToken authenticationToken = new AlipayMiniProgramAuthenticationToken(authorities,
				clientPrincipal, principal, user, additionalParameters, details, appid, code, userId);

		authenticationToken.setCredentials(credentials);

		return authenticationToken;
	}

	/**
	 * 根据 AppID(小程序ID)、code、jsCode2SessionUrl 获取Token
	 * @param appid AppID(小程序ID)
	 * @param code @see <a href=
	 * "https://opendocs.alipay.com/mini/api/openapi-authorize">my.getAuthCode获取用户信息授权，取得授权码（authCode）</a>
	 * @return 返回 Token及用户信息
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public AlipayMiniProgramTokenResponse getAccessTokenResponse(String appid, String code)
			throws OAuth2AuthenticationException {

		AlipayMiniProgramProperties.AlipayMiniProgram alipayConfig = getAlipayMiniProgramByAppid(appid);

		AlipayClient alipayClient;
		try {
			alipayClient = new DefaultAlipayClient(alipayConfig);
		}
		catch (AlipayApiException e) {
			OAuth2Error error = new OAuth2Error(OAuth2AlipayMiniProgramEndpointUtils.ERROR_CODE, "创建支付宝小程序配置异常",
					AUTH_ALIPAY_SYSTEM_OAUTH_TOKEN_URI);
			throw new OAuth2AuthenticationException(error);
		}

		AlipaySystemOauthTokenRequest systemOauthTokenRequest = new AlipaySystemOauthTokenRequest();
		systemOauthTokenRequest.setCode(code);
		systemOauthTokenRequest.setGrantType("authorization_code");

		AlipaySystemOauthTokenResponse systemOauthTokenResponse;
		try {
			systemOauthTokenResponse = alipayClient.execute(systemOauthTokenRequest);
		}
		catch (AlipayApiException e) {
			OAuth2Error error = new OAuth2Error(OAuth2AlipayMiniProgramEndpointUtils.ERROR_CODE, "支付宝小程序获取Token异常",
					AUTH_ALIPAY_SYSTEM_OAUTH_TOKEN_URI);
			throw new OAuth2AuthenticationException(error);
		}
		String systemOauthTokenResponseCode = systemOauthTokenResponse.getCode();

		String accessToken = systemOauthTokenResponse.getAccessToken();
		AlipayUserInfoShareRequest userInfoShareRequest = new AlipayUserInfoShareRequest();

		AlipayUserInfoShareResponse userInfoShareResponse;
		try {
			userInfoShareResponse = alipayClient.execute(userInfoShareRequest, accessToken);
		}
		catch (AlipayApiException e) {
			OAuth2Error error = new OAuth2Error(OAuth2AlipayMiniProgramEndpointUtils.ERROR_CODE, "支付宝小程序获取用户信息异常",
					AUTH_ALIPAY_USER_INFO_SHARE_URI);
			throw new OAuth2AuthenticationException(error);
		}
		String userInfoShareResponseCode = userInfoShareResponse.getCode();

		AlipayMiniProgramTokenResponse alipayMiniProgramTokenResponse = new AlipayMiniProgramTokenResponse();
		alipayMiniProgramTokenResponse.setSystemOauthTokenResponse(systemOauthTokenResponse);
		alipayMiniProgramTokenResponse.setUserInfoShareResponse(userInfoShareResponse);

		return alipayMiniProgramTokenResponse;
	}

	/**
	 * 根据 appid 获取 支付宝小程序属性配置
	 * @param appid 小程序ID
	 * @return 返回 支付宝小程序属性配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public AlipayMiniProgramProperties.AlipayMiniProgram getAlipayMiniProgramByAppid(String appid)
			throws OAuth2AuthenticationException {
		List<AlipayMiniProgramProperties.AlipayMiniProgram> list = alipayMiniProgramProperties.getList();
		if (list == null) {
			OAuth2Error error = new OAuth2Error(OAuth2AlipayMiniProgramEndpointUtils.ERROR_CODE, "appid 未配置", null);
			throw new AppidAlipayMiniProgramException(error);
		}

		for (AlipayMiniProgramProperties.AlipayMiniProgram alipayMiniProgram : list) {
			if (appid.equals(alipayMiniProgram.getAppId())) {
				return alipayMiniProgram;
			}
		}
		OAuth2Error error = new OAuth2Error(OAuth2AlipayMiniProgramEndpointUtils.ERROR_CODE, "未匹配到 appid", null);
		throw new AppidAlipayMiniProgramException(error);
	}

}
