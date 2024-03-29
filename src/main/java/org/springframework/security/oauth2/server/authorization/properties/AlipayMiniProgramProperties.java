package org.springframework.security.oauth2.server.authorization.properties;

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

import com.alipay.api.AlipayConfig;
import lombok.AccessLevel;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.server.authorization.client.AlipayMiniProgramService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * 支付宝小程序属性配置类
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Data
@Component
@ConfigurationProperties("alipay.mini.program")
public class AlipayMiniProgramProperties {

	/**
	 * 支付宝小程序属性配置列表
	 */
	private List<AlipayMiniProgram> list;

	/**
	 * 默认支付宝小程序的权限
	 * <p>
	 * 若要自定义用户的权限，请开发者自己实现 {@link AlipayMiniProgramService}
	 */
	private String defaultRole;

	/**
	 * 默认 AppID
	 */
	@Getter(AccessLevel.NONE)
	private String defaultAppid;

	public String getDefaultAppid() {
		if (StringUtils.hasText(defaultAppid)) {
			return defaultAppid;
		}
		if (list == null) {
			return null;
		}
		if (list.size() > 0) {
			return list.get(0).getAppId();
		}
		return null;
	}

	/**
	 * 支付宝小程序属性配置类
	 *
	 * @author xuxiaowei
	 * @since 0.0.1
	 */
	@Data
	@EqualsAndHashCode(callSuper = true)
	public static class AlipayMiniProgram extends AlipayConfig {

	}

}
