package ca.mrc0mm0n.ctrl;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
public class ArticlesController {

	private static final Logger logger = LoggerFactory.getLogger(ArticlesController.class);

	public ArticlesController(WebClient webClient) {
		this.webClient = webClient;
	}

	private WebClient webClient;

	@GetMapping(value = "/articles")
	public String[] getArticles(
			@RegisteredOAuth2AuthorizedClient("articles-client-authorization-code") OAuth2AuthorizedClient authorizedClient,
			@RequestHeader Map<String, String> headers) {
		logger.info(">> getArticles()");

		// logger.info("-- " + authorizedClient.getAccessToken().getTokenValue());

		headers.forEach((key, value) -> {
			logger.info(String.format("Header '%s' = %s", key, value));
		});

		logger.info("<< getArticles()");
		return this.webClient.get().uri("http://127.0.0.1:8090/articles")
				.attributes(oauth2AuthorizedClient(authorizedClient)).retrieve().bodyToMono(String[].class).block();
	}
}