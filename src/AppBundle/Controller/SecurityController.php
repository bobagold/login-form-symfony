<?php
namespace AppBundle\Controller;

use AppBundle\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\FormError;
use Symfony\Component\HttpFoundation\Request;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
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
            [
                // last username entered by the user
                'last_username' => $lastUsername,
                'error'         => $error,
            ]
        );
    }

    /**
     * @Route("/password_restore", name="password_restore")
     */
    public function passwordRestoreAction(Request $request)
    {
        $form = $this->createFormBuilder()
            ->add('email', EmailType::class, ['constraints' => [new NotBlank, new Email]])
            ->add('send', SubmitType::class, ['label' => 'Reset password'])
            ->getForm();
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $email = $form->get('email')->getData();

            $user = $this->get('app.password_service')->findUserByEmail($email);
            if (!$user) {
                $form->get('email')->addError(new FormError('email not found'));
            } else {
                $this->resetPassword($email, $user);

                return $this->redirectToRoute('login', ['message' => 'password_reset']);
            }
        }
        return $this->render(
            'security/password_restore.html.twig',
            [
                'form' => $form->createView()
            ]
        );
    }

    /**
     * @Route("/password_reset_confirm/{hash}", name="password_reset_confirm")
     */
    public function passwordResetConfirmAction($hash, Request $request)
    {
        $user = $this->get('app.password_service')->findUserByConfirmationHash($hash);
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
            ->add('password', RepeatedType::class, [
                'type' => PasswordType::class,
                'invalid_message' => 'The password fields must match.',
                'options' => ['attr' => ['class' => 'password-field'], 'constraints' => [new NotBlank()]],
                'required' => true,
                'first_options'  => ['label' => 'Password'],
                'second_options' => ['label' => 'Repeat Password'],
            ], ['constraints' => [new NotBlank()]])
            ->add('save', SubmitType::class, ['label' => 'Submit'])
            ->getForm();
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $this->get('app.password_service')->savePassword(
                $form->get('password')->getData(),
                $this->get('security.encoder_factory'),
                $this->get('security.token_storage')->getToken()->getUser()
            );
            return $this->redirectToRoute('logout');
        }
        return $this->render(
            'security/password_change.html.twig',
            [
                'form' => $form->createView()
            ]
        );
    }

    private function resetPassword($email, User $user)
    {
        $message = \Swift_Message::newInstance()
            ->setSubject($this->getParameter('password_restore_subject'))
            ->setFrom($this->getParameter('mailer_from'))
            ->setTo($email)
            ->setBody(
                $this->renderView(
                    'emails/forgot_password.html.twig',
                    ['hash' => $this->get('app.password_service')->generateConfirmationHash($user)]
                ),
                'text/html'
            );
        $this->get('mailer')->send($message);
    }
}
