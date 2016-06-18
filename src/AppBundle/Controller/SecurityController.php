<?php
namespace AppBundle\Controller;

use AppBundle\Entity\User;
use Doctrine\ORM\EntityManager;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\FormError;
use Symfony\Component\HttpFoundation\Request;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Validator\Constraints\Email;
use Symfony\Component\Validator\Constraints\NotBlank;

class SecurityController extends Controller
{
    /**
     * @Route("/login", name="login")
     */
    public function loginAction(Request $request)
    {
        $authenticationUtils = $this->get('security.authentication_utils');

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();

        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render(
            'security/login.html.twig',
            array(
                // last username entered by the user
                'last_username' => $lastUsername,
                'error'         => $error,
            )
        );
    }

    /**
     * @Route("/password_restore", name="password_restore")
     */
    public function passwordRestoreAction(Request $request)
    {
        $form = $this->createFormBuilder()
            ->add('email', EmailType::class, ['constraints' => [new NotBlank, new Email]])
            ->add('send', SubmitType::class, array('label' => 'Reset password'))
            ->getForm();
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $email = $form->get('email')->getData();

            $em = $this->getDoctrine()->getManager();

            $users = $em->getRepository('AppBundle:User')->findBy(['email' => $email]);
            if (!$users) {
                $form->get('email')->addError(new FormError('email not found'));
            } else {
                $this->resetPassword($email, $users[0]);
                return $this->redirectToRoute('login', ['message' => 'password_reset']);
            }
        }
        return $this->render(
            'security/password_restore.html.twig',
            array(
                'form' => $form->createView()
            )
        );
    }

    /**
     * @Route("/password_reset_confirm/{hash}", name="password_reset_confirm")
     */
    public function passwordResetConfirmAction($hash, Request $request)
    {
        $em = $this->getDoctrine()->getManager();

        $user = $this->findUserByConfirmationHash($em, $hash);
        if (!$user) {
            return $this->redirectToRoute('login');
        }
        $token = new UsernamePasswordToken($user, '', 'password_reset', ['ROLE_USER']);
        $this->get('security.token_storage')->setToken($token);
        return $this->redirectToRoute('password_change');
    }

    /**
     * @Route("/password_change", name="password_change")
     */
    public function passwordChangeAction(Request $request)
    {
        $form = $this->createFormBuilder()
            ->add('password', RepeatedType::class, array(
                'type' => PasswordType::class,
                'invalid_message' => 'The password fields must match.',
                'options' => array('attr' => array('class' => 'password-field'), 'constraints' => [new NotBlank()]),
                'required' => true,
                'first_options'  => array('label' => 'Password'),
                'second_options' => array('label' => 'Repeat Password'),
            ), ['constraints' => [new NotBlank()]])
            ->add('save', SubmitType::class, array('label' => 'Submit'))
            ->getForm();
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $this->savePassword(
                $form->get('password')->getData(),
                $this->get('security.encoder_factory'),
                $this->get('security.token_storage')->getToken()->getUser()
            );
            return $this->redirectToRoute('logout');
        }
        return $this->render(
            'security/password_change.html.twig',
            array(
                'form' => $form->createView()
            )
        );
    }

    private function resetPassword($email, User $user)
    {
        $em = $this->getDoctrine()->getManager();
        $message = \Swift_Message::newInstance()
            ->setSubject('Hello Email')
            ->setFrom('vgold@xiag.ch')
            ->setTo('vgold@xiag.ch')
            ->setBody(
                $this->renderView(
                    'emails/forgot_password.html.twig',
                    array('name' => $email, 'hash' => $this->generateConfirmationHash($em, $user))
                ),
                'text/html'
            )
        ;
        $this->get('mailer')->send($message);
    }

    private function savePassword($password, EncoderFactoryInterface $encoder, User $user)
    {
        $user->setPassword($encoder->getEncoder($user)->encodePassword($password, null));
        $em = $this->getDoctrine()->getManager();
        $em->persist($user);
        $em->flush();
    }

    private function generateConfirmationHash(EntityManager $em, User $user)
    {
        $user->setConfirmationHash(uniqid());
        $em = $this->getDoctrine()->getManager();
        $em->persist($user);
        $em->flush();
        return $user->getConfirmationHash();
    }

    private function findUserByConfirmationHash(EntityManager $em, $hash)
    {
        $users = $em->getRepository('AppBundle:User')->findBy(['confirmation_hash' => $hash]);
        return $users ? $users[0] : null;
    }
}
