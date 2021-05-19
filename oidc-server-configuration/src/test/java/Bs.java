import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

public class Bs {

    public static void main(String[] args) {
        MultiValueMap<String, String> v = new LinkedMultiValueMap<>();
        String s = v.getFirst("bb");
        System.out.println(s);
    }
}
