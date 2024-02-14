package ca.mrc0mm0n.ctrl;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class NavCtrl {

	private static final Logger logger = LoggerFactory.getLogger(NavCtrl.class);

	@GetMapping("/")
	public ModelAndView index(@RequestHeader Map<String, String> headers, ModelAndView modelView, Authentication auth) {
		logger.debug(">> index()");

		headers.forEach((key, value) -> {
			logger.debug("-- " + String.format("Header '%s' = %s", key, value));
		});

		logger.debug("-- " + auth);

		modelView.addObject("auth", auth);

		modelView.setViewName("index");

		logger.debug("<< index()");
		return modelView;
	}

}